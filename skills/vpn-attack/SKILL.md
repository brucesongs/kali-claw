---
name: vpn-attack
description: "Virtual Private Networks (VPNs) are a critical component of enterprise network security, providing encrypted tunnels for remote access and site-to-site connectivity."
origin: openclaw
version: "0.1.21"
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
  - Agent
metadata:
  domain: security
  tool_count: 5
  guide_count: 3
---



# Skill: VPN Attack

> **Supplementary Files**:
> - `payloads.md` — Payload collection organized by 12 VPN attack categories (IKE enumeration, PSK cracking, transform set discovery, SSL VPN exploitation, tunnel testing, certificate attacks, credential brute force, tunnel hijacking, split tunneling detection, client config testing, detection avoidance)
> - `test-cases.md` — Structured test case templates (8 cases covering IKE enumeration, aggressive mode PSK cracking, transform set discovery, SSL VPN enumeration, IPSec tunnel testing, certificate analysis, credential brute force, split tunneling detection)
> - `guides/ipsec-vpn-enumeration-fingerprinting-guide.md` — IPSec VPN reconnaissance and fingerprinting complete guide
> - `guides/ssl-vpn-exploitation-guide.md` — SSL VPN attack techniques guide
> - `guides/vpn-credential-tunnel-attack-guide.md` — VPN credential and tunnel attack guide

## Summary

Vpn Attack skill domain covering security operations.

**Tools**: ike-scan, ikeforce, ikecrack, vpnc, strongswan

**Domain**: security

## Description

Virtual Private Networks (VPNs) are a critical component of enterprise network security, providing encrypted tunnels for remote access and site-to-site connectivity. This skill covers the full spectrum of VPN attack methodologies targeting IPSec/IKE, SSL/TLS-based VPNs, and related infrastructure. Attackers exploit weak pre-shared keys, misconfigured IKE parameters, certificate handling flaws, and implementation vulnerabilities to gain unauthorized access or intercept VPN traffic.

The attack surface includes IKE Phase 1 and Phase 2 negotiations, VPN gateway web interfaces, authentication mechanisms (PSK, certificates, XAUTH), tunnel configuration parameters, and client-side vulnerabilities. Understanding these attack vectors is essential for both offensive security testing and defensive hardening of VPN deployments.

## Use Cases

1. **Enterprise VPN penetration testing** — Assess the security posture of corporate VPN gateways, identify weak configurations, and test authentication mechanisms during authorized engagements
2. **IKE/IPSec security assessment** — Enumerate supported transform sets, identify aggressive mode configurations vulnerable to offline PSK cracking, and test for IKE implementation flaws
3. **SSL VPN gateway testing** — Evaluate web-based VPN portals for known CVEs, authentication bypass, and session management weaknesses across vendors (Fortinet, Pulse Secure, Palo Alto, Cisco)
4. **VPN credential auditing** — Test pre-shared key strength through offline cracking, audit certificate management practices, and assess XAUTH credential policies
5. **Network lateral movement via VPN** — Test tunnel hijacking, split tunneling exploitation, and routing manipulation to assess the impact of compromised VPN access
6. **VPN hardening guidance** — Provide actionable remediation recommendations based on discovered vulnerabilities to strengthen VPN infrastructure

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **ike-scan** | IKE enumeration, fingerprinting, and transform set discovery | `ike-scan -M -A --id=vpn --pskcrack target` |
| **ikeforce** | Aggressive mode PSK brute force and VPN enumeration | `ikeforce.py target -e -i vpn_id -w wordlist.txt` |
| **ikecrack** | Offline IKE PSK cracking from captured exchanges | `ikecrack -p psk_hash.txt -w dictionary.txt` |
| **vpnc** | IPSec VPN client for testing connectivity and configurations | `vpnc --local-port 0 /etc/vpnc/test.conf` |
| **strongswan** | Full IPSec stack for advanced VPN testing and tunnel manipulation | `swanctl --load-all --initiate --ike home` |

## Methodology

### Attack Chain

```
Discovery → Enumeration → Authentication Attack → Tunnel Exploitation → Post-VPN Access
```

**1. Discovery (Identify VPN gateways)**
- Port scan for IKE (UDP 500, 4500), SSL VPN (TCP 443, 8443, 10443)
- Identify VPN vendors via banner grabbing, certificate analysis, and web interface fingerprinting
- Detect supported protocols: IPSec/IKEv1, IKEv2, SSL/TLS, PPTP, L2TP

**2. Enumeration (Gather VPN parameters)**
- Enumerate IKE transform sets using ike-scan with different encryption/hash/DH group combinations
- Identify IKE mode (aggressive vs main) to determine PSK cracking feasibility
- Discover valid VPN identifiers (group names, tunnel IDs) for aggressive mode
- Fingerprint VPN gateway vendor and version via Vendor ID payloads

**3. Authentication Attack (Compromise credentials)**
- Aggressive mode PSK capture and offline cracking with ikecrack/ikeforce
- XAUTH credential brute force against IKE Phase 1 authenticated sessions
- SSL VPN portal credential testing and authentication bypass
- Certificate-based attacks: forged certificates, CA compromise analysis

**4. Tunnel Exploitation (Abuse established tunnels)**
- Split tunneling detection and exploitation for routing manipulation
- Tunnel hijacking via session injection or routing table manipulation
- Inner IP address enumeration and lateral movement within VPN network
- DNS and traffic interception through compromised tunnel

**5. Post-VPN Access (Persistence and lateral movement)**
- Internal network enumeration through VPN tunnel
- Privilege escalation on VPN gateway management interface
- Persistence via saved VPN profiles or credential harvesting
- Data exfiltration through established encrypted tunnel

### Defense Perspective

| Defense Measure | Description | Priority |
|-----------------|-------------|----------|
| Disable Aggressive Mode | Use Main Mode or IKEv2 to prevent PSK exposure in clear text | CRITICAL |
| Strong Pre-Shared Keys | Use 20+ character random PSKs; consider certificate-based authentication | CRITICAL |
| Certificate-Based Auth | Deploy PKI with proper CA management; use EAP-TLS or certificate-based IKE | HIGH |
| VPN Gateway Patching | Keep VPN appliances updated; monitor CVEs for Fortinet, Pulse Secure, Palo Alto, Cisco | CRITICAL |
| Split Tunneling Controls | Disable split tunneling or implement strict routing policies | HIGH |
| Multi-Factor Authentication | Require MFA for all VPN connections; use time-based OTP or push notifications | HIGH |
| Network Segmentation | Restrict VPN user access via ACLs; limit lateral movement within VPN network | HIGH |
| VPN Session Monitoring | Log and monitor VPN connections, failed authentications, and unusual patterns | MEDIUM |
| Dead Peer Detection | Enable DPD to detect and clean up stale IKE sessions | MEDIUM |
| IKEv2 Migration | Prefer IKEv2 over IKEv1 for improved security and NAT traversal | HIGH |

## Practical Steps

> **See `payloads.md` for detailed payloads and `test-cases.md` for complete test checklists.** Below is a summary of core operations at each stage.

### Step 1: VPN Discovery and Port Scanning

```bash
# Discover IKE (IPSec) VPN gateways
nmap -sU -p 500,4500,1701 --script=ike-version target_network/24

# Discover SSL VPN portals
nmap -sS -p 443,8443,10443,4443,9443 --script=ssl-cert,http-title target_network/24

# Identify IKE vendor via ike-scan
ike-scan -M target

# Comprehensive VPN service identification
nmap -sU -sS -p 500,4500,1701,443,8443 --script=ike-version,ssl-cert target
```

### Step 2: IKE Enumeration and Fingerprinting

```bash
# Enumerate IKE transform sets with ike-scan
ike-scan -M --trans=(1=2,2=1,3=1,4=1) target
ike-scan -M --trans=(1=2,2=2,3=1,4=2) target
ike-scan -M --trans=(1=5,2=1,3=2,4=1) target

# Fingerprint VPN gateway vendor
ike-scan -M --showbackoff target

# Test for aggressive mode with various VPN IDs
ike-scan -M -A --id=vpn target
ike-scan -M -A --id=cisco target
ike-scan -M -A --id=group1 target
```

### Step 3: PSK Cracking

```bash
# Capture aggressive mode handshake for offline cracking
ike-scan -M -A --id=vpn --pskcrack target > psk_capture.txt

# Crack captured PSK with ikecrack
ikecrack -p psk_capture.txt -w /usr/share/wordlists/rockyou.txt

# Brute force with ikeforce
ikeforce.py target -e -i vpn_id -w /usr/share/wordlists/rockyou.txt

# Hashcat mode for PSK cracking (if converted to proper format)
hashcat -m 5300 psk_hash.txt /usr/share/wordlists/rockyou.txt
```

### Step 4: SSL VPN Testing

```bash
# Enumerate SSL VPN web interface
curl -k https://target:443/
curl -k https://target:10443/remote/logincheck

# Check SSL/TLS configuration
openssl s_client -connect target:443 -tls1
openssl s_client -connect target:443 -tls1_2

# Test for known SSL VPN CVEs
nmap -sS -p 443 --script=http-vuln* target

# Capture and analyze VPN portal traffic
tcpdump -i eth0 -w ssl_vpn_capture.pcap host target and port 443
```

### Step 5: VPN Client Configuration Testing

```bash
# Test IPSec connectivity with vpnc
cat > /tmp/test_vpn.conf << 'EOF'
IKE DH Group dh2
IKE Cipher aes256
IKE Hash md5
IPSec Cipher aes256
IPSec Hash sha1
Domain vpn_domain
Vendor cisco
Host target_ip
AuthType psk
Group vpn_group
GroupPassword <cracked_psk>
Xauth username testuser
Xauth password testpass
EOF
vpnc --local-port 0 /tmp/test_vpn.conf

# Test with strongswan (swanctl)
swanctl --load-all
swanctl --initiate --ike test_tunnel
```

## Learning Resources

**Skill supplementary files**:
- `payloads.md` — Complete payload collection (12 VPN attack categories, ready to copy for testing)
- `test-cases.md` — Structured test case templates (8 cases with prerequisites and expected results)
- `guides/ipsec-vpn-enumeration-fingerprinting-guide.md` — IPSec VPN reconnaissance and fingerprinting guide
- `guides/ssl-vpn-exploitation-guide.md` — SSL VPN attack techniques guide
- `guides/vpn-credential-tunnel-attack-guide.md` — VPN credential and tunnel attack guide

**Related Skills**:
- `skills/network-pentest/SKILL.md` — Network penetration testing fundamentals
- `skills/network-tunneling-proxy/SKILL.md` — Network tunneling and proxy techniques
- `skills/password-attack/SKILL.md` — Password attack methodologies
- `skills/crypto-attacks/SKILL.md` — Cryptographic attack techniques

**External Resources**:
- [RFC 7296 - IKEv2](https://tools.ietf.org/html/rfc7296)
- [IKE Scanner Documentation](https://github.com/royhills/ike-scan)
- [NIST SP 800-77 - IPSec VPN Guide](https://csrc.nist.gov/publications/detail/sp/800-77/rev-1/final)
- [CISA Advisory - VPN Security](https://www.cisa.gov/news-events/cybersecurity-advisories)
- [HackTricks - IPSec/IKE Pentesting](https://book.hacktricks.xyz/pentesting/pentesting-ipsec-ike-vpn)
