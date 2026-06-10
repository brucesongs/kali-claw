---
name: network-sniffing-mitm
description: "Network Sniffing and MITM attacks focus on intercepting, analyzing, and manipulating network traffic between two communicating parties."
origin: openclaw
version: "0.1.18"
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
  tool_count: 10
  guide_count: 3
  mitre: "TA0006-Credential Access"
---




# Skill: Network Sniffing and Man-in-the-Middle (MITM)

> **Supplementary Files**:
> - `payloads.md` — Attack payload collection: passive capture, ARP spoofing, DNS spoofing, credential harvesting, SSL stripping, caplet scripting, and traffic manipulation commands
> - `test-cases.md` — Structured test cases: TC-NSM-001 through TC-NSM-006 covering passive capture, ARP spoof MITM, responder credential harvest, bettercap caplets, DNS spoofing, and HTTPS downgrade

## Summary

Network Sniffing Mitm skill domain covering network attack operations.

**Tools**: wireshark/tshark, tcpdump, ettercap, bettercap, mitm6, responder, dsniff, driftnet (+2 more)

**Domain**: network-attack

**MITRE ATT&CK**: TA0006-Credential Access

## Description

Network Sniffing and MITM attacks focus on intercepting, analyzing, and manipulating network traffic between two communicating parties. This skill covers the full spectrum from passive packet capture (undetectable on shared media) through active man-in-the-middle positioning (ARP/NDP/DNS spoofing) to credential harvesting and traffic manipulation. The attacker positions themselves on the network path between victim and destination, enabling plaintext inspection of otherwise trusted communications.

**Core Insight**: MITM attacks exploit trust at Layer 2 and Layer 3 of the OSI model. ARP has no authentication, LLMNR/NBT-NS are fallback protocols that respond to any query, and IPv6 is often enabled by default with no security controls. These design assumptions create a wide attack surface on internal networks. A successful MITM position gives the attacker the same visibility as the network infrastructure itself.

**Key Attack Surfaces**:

- **ARP Protocol**: Stateless, unauthenticated — any host can claim any IP address by sending unsolicited ARP replies. Dynamic ARP Inspection (DAI) mitigates but is often not deployed.
- **LLMNR/NBT-NS/mDNS**: Windows fallback name resolution protocols broadcast queries when DNS fails. An attacker responds first and captures NTLM authentication hashes.
- **IPv6 SLAAC**: Windows prefers IPv6 over IPv4 by default. An attacker advertising a rogue IPv6 router becomes the preferred gateway without any IPv4 MITM.
- **DHCP**: Rogue DHCP servers hand out attacker-controlled DNS and gateway addresses to new clients on the network.
- **SSL/TLS Stripping**: Downgrading HTTPS to HTTP by rewriting URLs and stripping security headers before the client's first request reaches the server.
- **DNS Spoofing**: Responding to DNS queries with attacker-controlled IP addresses redirects victims to malicious services.

---

## Use Cases

1. **Internal Network Assessment** — Position between victim hosts and gateway to capture cleartext credentials (FTP, HTTP, SMTP, IMAP) and analyze protocol usage across the environment.
2. **Active Directory Credential Harvesting** — Poison LLMNR/NBT-NS/mDNS to collect NTLMv2 hashes from Windows clients, then crack offline or relay to other systems via SMB relay.
3. **Application Security Testing** — Intercept and modify HTTP/HTTPS traffic between a client and web application to test input validation, session handling, and API security.
4. **IPv6 Attack Surface Validation** — Use mitm6 to test whether IPv6 is enabled and exploitable in a predominantly IPv4 network, then chain with LDAP/SMB relay for domain escalation.
5. **Network Forensics and Incident Response** — Capture and analyze full PCAP to reconstruct communication timelines, extract transferred files, and identify data exfiltration.
6. **Traffic Manipulation and Injection** — Use bettercap caplets or mitmproxy scripts to inject JavaScript, modify responses, or replace downloaded files in transit.

---

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **wireshark/tshark** | Protocol analysis, PCAP triage, credential extraction, protocol hierarchy statistics | `tshark -r capture.pcap -Y "http.request"` |
| **tcpdump** | Lightweight packet capture with BPF filters, suitable for long-duration sniffing | `tcpdump -i eth0 -w capture.pcap` |
| **ettercap** | Classic ARP spoofing MITM tool with plugin system for SSL stripping and filtering | `ettercap -T -q -i eth0 -M arp:remote /target// /gateway//` |
| **bettercap** | Modular MITM framework with caplet scripting, ARP/DNS/DHCP spoofing, and credential sniffer | `bettercap -iface eth0` |
| **mitm6** | IPv6 MITM via SLAAC rogue router advertisement, chains to NTLM relay | `mitm6 -d domain.local -i eth0` |
| **responder** | LLMNR/NBT-NS/mDNS poisoner, captures NTLMv1/v2 hashes, HTTP/FTP/SMB auth | `responder -I eth0 -w -d -f` |
| **dsniff** | Suite of network sniffing tools: arpspoof, dnsspoof, urlsnarf, filesnarf, mailsnarf | `arpspoof -i eth0 -t victim gateway` |
| **driftnet** | Extracts images from HTTP traffic in real-time for visual reconnaissance | `driftnet -i eth0 -d /tmp/images` |
| **mitmproxy** | Interactive HTTPS proxy with Python scripting API for traffic analysis and modification | `mitmproxy -p 8080 --mode transparent` |

---

## Methodology

### Attack Chain

```
  Survey              Capture              Poison              Harvest
 (arp-scan)    →   (tcpdump/tshark)  →  (ettercap/bettercap)  →  (responder/dsniff)
                                                                    │
         Manipulate          Exfiltrate                            │
  (bettercap caplets) ←  (driftnet/filesnarf)  ←─────────────────┘
```

**Phase Details**:

1. **Survey** — Map the network topology using ARP scanning (`arp-scan -l`) and passive traffic observation. Identify the gateway IP, target hosts, VLAN structure, and any existing security controls (DAI, port security, 802.1X). Document MAC addresses and IP-to-host mappings for targeting.

2. **Capture** — Begin passive packet capture with tcpdump or tshark. Apply BPF/display filters to focus on target protocols. Identify cleartext services (HTTP, FTP, SMTP, IMAP, Telnet) and record credential patterns. This phase is completely undetectable on switched networks when using port mirroring or when operating on a hub/shared medium.

3. **Poison** — Establish MITM position through ARP spoofing (ettercap/bettercap), IPv6 SLAAC (mitm6), or DHCP spoofing. Select the poisoning technique based on the target environment: ARP spoof for Layer 2 adjacency, mitm6 for Windows domains with IPv6 enabled, or DNS spoof for targeted domain redirection.

4. **Harvest** — With MITM position established, run protocol-specific credential harvesters: Responder for LLMNR/NBT-NTLM hashes, dsniff for FTP/HTTP/Telnet credentials, bettercap sniffer module for API keys and cookies. Collect and categorize all harvested credentials.

5. **Manipulate** — Use bettercap caplets or mitmproxy scripts to modify traffic in transit: inject JavaScript into HTTP responses, replace file downloads, strip HTTPS to HTTP, or modify DNS responses. This phase demonstrates the impact of a MITM position beyond passive observation.

6. **Exfiltrate** — Extract images (driftnet), files (filesnarf), emails (mailsnarf), and URLs (urlsnarf) from intercepted traffic. Correlate captured data with host identities for reporting.

### Defense Perspective

- **Dynamic ARP Inspection (DAI)** — Switches validate ARP packets against a trusted DHCP snooping binding database, dropping spoofed ARP replies.
- **Port Security** — Limit the number of MAC addresses per switch port to prevent MAC flooding attacks that force switches into hub mode.
- **802.1X Network Access Control** — Require authentication before a device can communicate on the network, preventing rogue device placement.
- **DNSSEC / DNS-over-HTTPS** — Cryptographic DNS response validation prevents spoofing; encrypted DNS prevents inspection-based manipulation.
- **Certificate Pinning / HSTS** — Prevent SSL stripping by requiring HTTPS connections and rejecting certificate mismatches.
- **LLMNR/NBT-NS Disabling** — Group Policy can disable these fallback protocols across all domain-joined machines.
- **IPv6 Hardening** — Disable IPv6 where not required, or deploy RA Guard to block rogue router advertisements.

---

## Key Decisions

| Decision | Options | Recommendation |
|----------|---------|----------------|
| **Capture tool** | tcpdump vs tshark | Use tcpdump for long captures and remote/headless systems; use tshark for protocol-aware analysis and credential extraction |
| **MITM framework** | ettercap vs bettercap | Prefer bettercap for active engagements (modern, modular, caplet scripting). Use ettercap for quick ARP spoof tests or when bettercap is unavailable |
| **Poisoning technique** | ARP spoof vs mitm6 vs DNS spoof | Use mitm6 for Windows domain environments (IPv6 preferred over IPv4). Use ARP spoof for non-Windows targets. Use DNS spoof for targeting specific domains |
| **SSL stripping** | sslstrip vs bettercap vs mitmproxy | Use bettercap's `net.sniff` with `http.proxy` for integrated MITM+strip. Use mitmproxy for application-level testing with scriptable modifications |
| **Credential cracking** | hashcat vs john | Prefer hashcat for GPU-accelerated NTLMv2 (mode 5600) and large wordlists. Use john for quick tests and when GPU is unavailable |

---

## Quality Criteria

- **Topology mapping** is complete: all live hosts, gateway, DNS servers, and VLAN boundaries documented before active attack begins.
- **Passive capture** runs for a meaningful duration (minimum 5 minutes, ideally 30+ minutes) to establish baseline traffic patterns.
- **MITM position** is verified with connectivity testing: target can still reach the internet, and attacker can see the traffic flowing through.
- **Credential harvesting** results are categorized by protocol, host, and hash type. Hashes are tested for cracking feasibility before reporting.
- **Impact demonstration** goes beyond capturing hashes: shows plaintext credential exposure, session token theft, or traffic manipulation outcomes.
- **Cleanup** is thorough: ARP caches return to normal, no poisoned routes remain, and all captured data is securely stored and eventually destroyed per engagement scope.

---

## Common Pitfalls

- **Forgetting IP forwarding**: Without `echo 1 > /proc/sys/net/ipv4/ip_forward`, ARP spoofing creates a denial of service instead of a transparent MITM. The target loses all connectivity.
- **Aggressive ARP spoofing on large networks**: Spoofing the entire subnet generates massive ARP traffic that triggers network monitoring alerts and can degrade switch performance. Target specific hosts instead.
- **Ignoring IPv6**: Windows prefers IPv6 over IPv4. Running only IPv4 ARP spoofing misses half the traffic. Always check IPv6 with `mitm6` in Windows environments.
- **Attempting SSL stripping on HSTS sites**: Modern browsers with HSTS preloaded lists will refuse HTTP connections regardless of stripping. Focus on non-HSTS targets or use certificate-based MITM instead.
- **Not verifying MITM position**: Attackers assume MITM is working without confirmation. Always verify by capturing a known test request from the target (e.g., trigger an HTTP request and confirm it appears in tcpdump).
- **Leaving Responder running too long**: Extended Responder sessions capture excessive hashes and may trigger account lockout policies. Collect what is needed, then stop.

---

## Automation and Scripting

Automate the full MITM workflow with bettercap caplets that chain discovery, poisoning, sniffing, and reporting into a single script. For credential harvesting, pipe Responder output into hashcat for real-time cracking attempts. Use tcpdump with ring buffers (`-G` and `-W` flags) for continuous long-duration capture that rotates PCAP files. Write tshark one-liners with `-T fields -e` to extract specific credential fields from live traffic or saved PCAP files for automated reporting.

---

## Reporting and Documentation

MITM findings should document the specific technique used (ARP/IPv6/DNS spoofing), the network segment affected, and the duration of the MITM position. For credential harvesting, report the hash type, the account context (local vs domain), and the cracking result. Never include unredacted passwords in reports — report only that "Account X was compromised" and provide the hash separately in a secure channel. For traffic manipulation findings, include before/after screenshots showing the injected content or modified responses.

---

## Legal and Ethical Considerations

MITM attacks and traffic interception are among the most sensitive penetration testing activities. Obtain explicit written authorization that specifically permits traffic interception, credential harvesting, and active manipulation. Many jurisdictions consider unauthorized packet sniffing to be illegal wiretapping, even on corporate networks. Never capture traffic from networks or hosts outside the defined scope. Immediately delete captured PCAP files and credentials after the engagement unless the client explicitly requests retention for forensic purposes.

---

## Integration with Other Skills

Network sniffing and MITM results feed directly into multiple adjacent skills. Captured NTLM hashes chain into the password-attack skill for offline cracking with hashcat. Discovered cleartext protocols inform the vulnerability-assessment skill for prioritizing encryption upgrades. MITM traffic analysis reveals web application session tokens that feed into web-access-control for session hijacking tests. IPv6 findings from mitm6 connect to post-exploitation when chained with ntlmrelayx for domain escalation. DNS spoofing results inform the dns-attacks skill for deeper DNS security assessment.

---

## Case Studies and Examples

- **LLMNR Poisoning in a Corporate Network**: During an internal assessment, Responder captured 47 unique NTLMv2 hashes within 15 minutes. One hash belonged to a domain service account that had local administrator privileges on 23 workstations. After cracking the hash offline (8-character password, cracked in 3 minutes), full lateral movement was achieved across the entire floor.
- **SSL Stripping on a Guest Wi-Fi Network**: bettercap's SSL stripping module was used on a guest Wi-Fi to demonstrate that a popular SaaS application's login page was vulnerable to credential theft. The finding led to the application being reconfigured with HSTS preloading.
- **mitm6 to LDAP Relay**: In an Active Directory environment where LLMNR was disabled, mitm6 was used to establish an IPv6 MITM position. Chaining with ntlmrelayx targeting LDAPS on the domain controller, a new computer account was created with resource-based constrained delegation, leading to full domain compromise without any cracked passwords.

---

## Detection Methods

Understanding detection helps testers operate more effectively and helps defenders build monitoring. ARP spoofing is detected by tools that track MAC-to-IP mapping changes (arpwatch, switch DAI). LLMNR/NBT-NS poisoning generates Windows Event ID 4697. Rogue IPv6 router advertisements are detected by RA Guard on managed switches. SSL stripping leaves artifacts in browser security indicators (missing padlock, http:// URLs for known HTTPS sites). Unusually high ARP traffic volume is a reliable indicator of ARP spoofing across a subnet.

---

## Defense Evasion Techniques

Evade MITM detection during authorized testing by: targeting specific hosts rather than the entire subnet (reduces ARP noise), using bettercap's `set arp.spoof.internal false` to avoid poisoning inter-host traffic, employing selective DNS spoofing that only responds to specific domain queries, and using mitm6 instead of ARP spoofing in environments with IPv4-focused monitoring. For credential harvesting, run Responder with `--lm` to capture only LM hashes (less noisy) or in analysis mode (`-A`) first to identify opportunities before active poisoning.

---

## Tool Comparison Matrix

| Tool | Best For | Stealth | Detection Risk | Skill Level |
|------|----------|---------|-----------------|-------------|
| **tcpdump** | Passive capture, BPF filtering | High (passive) | Low | Intermediate |
| **tshark** | Protocol-aware PCAP analysis | High (passive) | Low | Intermediate |
| **ettercap** | Quick ARP spoofing tests | Low (noisy ARP) | Moderate | Beginner |
| **bettercap** | Full MITM with caplet scripting | Moderate | Moderate | Advanced |
| **mitm6** | Windows domain IPv6 MITM | High (often unmonitored) | Low | Intermediate |
| **responder** | Passive LLMNR/NBT-NS poisoning | High (passive) | Low | Beginner |
| **dsniff** | Lightweight protocol sniffing | Moderate | Moderate | Intermediate |
| **mitmproxy** | HTTP/HTTPS traffic manipulation | N/A (proxy mode) | Low | Advanced |
| **driftnet** | Visual traffic reconnaissance | High (passive) | Low | Beginner |

---

## Learning Resources

- **Skill supplementary files**: payloads.md, test-cases.md
- **Guides**: `guides/ettercap-bettercap-mitm-attack-guide.md`, `guides/wireshark-tshark-protocol-analysis-guide.md`, `guides/responder-mitm6-credential-harvesting-guide.md`
- **Related Skills**: skills/network-pentest/SKILL.md, skills/password-attack/SKILL.md, skills/post-exploitation/SKILL.md
- **External Resources**:
  - [Bettercap Official Documentation](https://www.bettercap.org/) — MITM framework complete reference
  - [Wireshark Wiki](https://gitlab.com/wireshark/wireshark/-/wikis/home) — tshark and Wireshark protocol analysis
  - [Responder GitHub](https://github.com/SpiderLabs/Responder) — LLMNR/NBT-NS/mDNS poisoner
  - [mitm6 Research Paper](https://fox-it.com/blog/2018/01/11/mitm6-combining-ipv4-and-ipv6/) — Fox-IT research on IPv6 MITM
  - [tcpdump Manual](https://www.tcpdump.org/manpages/tcpdump.1.html) — BPF filter syntax reference
  - [mitmproxy Documentation](https://docs.mitmproxy.org/) — Interactive HTTPS proxy scripting guide
