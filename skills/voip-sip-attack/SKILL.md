---
name: voip-sip-attack
description: "Voice over IP (VoIP) systems use the Session Initiation Protocol (SIP) for call signaling, the Real-time Transport Protocol (RTP) for media streaming, and the Inter-Asterisk eXchange protocol (IAX2) for alternative VoIP communication."
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
  domain: voip
  tool_count: 8
  guide_count: 3
  mitre: "TA0046-Initial Access"
---

# VoIP/SIP Attack

> **Supplementary Files**:
> - `payloads.md` — Attack payloads organized by category (SIP recon, extension enumeration, password cracking, eavesdropping, DoS, VLAN hopping)
> - `test-cases.md` — Structured test case templates (8 cases covering scanning, enumeration, cracking, VLAN hopping, DoS, RTP interception)
> - `guides/sip-device-recon.md` — SIP device reconnaissance deep dive
> - `guides/voip-eavesdropping-spoofing.md` — VoIP eavesdropping and spoofing techniques
> - `guides/voip-denial-of-service.md` — VoIP DoS attack methods and defenses

## Summary

Voip Sip Attack skill domain covering voip operations.

**Tools**: svmap, svwar, svcrack, sipsak, voiphopper, iaxflood, inviteflood, rtpflood

**Domain**: voip

**MITRE ATT&CK**: TA0046-Initial Access

## Description

Voice over IP (VoIP) systems use the Session Initiation Protocol (SIP) for call signaling, the Real-time Transport Protocol (RTP) for media streaming, and the Inter-Asterisk eXchange protocol (IAX2) for alternative VoIP communication. These protocols were designed for functionality, not security, making VoIP infrastructure a high-value target during penetration tests.

Common VoIP vulnerabilities include weak authentication on SIP endpoints, unencrypted RTP streams susceptible to eavesdropping, predictable extension numbering schemes, and protocol-level denial-of-service weaknesses. VoIP systems often sit on dedicated VLANs, but VLAN hopping techniques can bypass this segmentation.

**Core Protocols**:

- **SIP (Session Initiation Protocol)**: Application-layer signaling protocol for establishing, modifying, and terminating multimedia sessions. Operates over UDP/TCP port 5060 (plaintext) or 5061 (TLS). Digest authentication is optional and frequently misconfigured.
- **RTP (Real-time Transport Protocol)**: Carries audio and video media streams. Typically uses UDP on dynamically negotiated ports (often 10000-20000). Rarely encrypted, making interception straightforward when network access is obtained.
- **IAX2 (Inter-Asterisk eXchange v2)**: Protocol used primarily between Asterisk PBX servers. Single UDP port (4569) carries both signaling and media. Less common than SIP but found in Asterisk deployments.

---

## Use Cases

1. **VoIP Infrastructure Assessment**: Discover SIP devices, enumerate extensions, test authentication strength, and identify misconfigurations in PBX deployments during authorized network penetration tests.
2. **VoIP Eavesdropping Testing**: Intercept RTP media streams to demonstrate the risk of unencrypted voice traffic and validate whether encryption mechanisms (SRTP, TLS) are properly deployed.
3. **Denial-of-Service Testing**: Flood SIP, RTP, or IAX2 services to assess resilience of VoIP infrastructure against volumetric attacks and measure failover behavior.
4. **VLAN Segmentation Validation**: Use VoIP-specific VLAN hopping techniques to verify that voice and data VLANs are properly isolated and that trunk ports are secured.
5. **PBX Configuration Audit**: Test SIP registration processes, identify default credentials, enumerate valid extensions, and verify that authentication is enforced on all SIP methods.
6. **Red Team VoIP Exploitation**: Combine VoIP weaknesses into attack chains — VLAN hop to voice network, enumerate extensions, crack credentials, intercept calls, or disrupt services.

---

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **svmap** (sipvicious) | SIP device scanning and fingerprinting on a network range | `svmap 10.0.0.0/24` |
| **svwar** (sipvicious) | SIP extension enumeration via OPTIONS/REGISTER probing | `svwar -e 100-999 10.0.0.1` |
| **svcrack** (sipvicious) | SIP password cracking against registered extensions | `svcrack -u 100 -d wordlist.txt 10.0.0.1` |
| **sipsak** | SIP Swiss-army knife: probing, tracing, message sending, fuzzing | `sipsak -s sip:100@target.lab` |
| **voiphopper** | VLAN hopping into VoIP networks via CDP, DHCP, or 802.1Q | `voiphopper -i eth0 -C` |
| **iaxflood** | IAX2 protocol flood for DoS testing against Asterisk PBX | `iaxflood 10.0.0.1 4569 1000` |
| **inviteflood** | SIP INVITE flood for DoS testing against SIP proxies/UAs | `inviteflood -i eth0 10.0.0.1 10.0.0.5 100@target.lab 10000` |
| **rtpflood** | RTP packet flood for disrupting media streams | `rtpflood 10.0.0.1 10000 1000` |

---

## Methodology

### Attack Chain

```
Discovery → Enumeration → Authentication Testing → Eavesdropping → DoS Assessment → Reporting
```

### Phase 1: Discovery

1. Identify VoIP infrastructure on the target network using ARP scanning and port scanning (UDP 5060/5061/4569).
2. Use `svmap` to scan network ranges for live SIP devices and fingerprint their User-Agent headers.
3. Identify PBX type and version from SIP responses (Asterisk, Cisco CME, Avaya, FreeSWITCH, etc.).

### Phase 2: Enumeration

1. Use `svwar` to enumerate valid SIP extensions across likely ranges (100-999, 1000-1999, etc.).
2. Probe SIP services with `sipsak` to gather server capabilities, supported methods, and authentication requirements.
3. Identify which extensions require authentication and which respond without credentials.

### Phase 3: Authentication Testing

1. Use `svcrack` to perform dictionary and brute-force attacks against authenticated SIP extensions.
2. Test for default credentials (common PBX defaults: admin/admin, 100/100, etc.).
3. Attempt registration with discovered credentials to confirm access.

### Phase 4: Eavesdropping and Spoofing

1. Capture RTP streams on the voice VLAN using network sniffing tools.
2. Decode intercepted RTP audio from PCAP captures.
3. Test SIP caller ID spoofing by crafting custom INVITE requests with `sipsak`.
4. Validate VLAN segmentation with `voiphopper` — hop to voice VLAN and assess reachability.

### Phase 5: Denial-of-Service Assessment

1. Test SIP INVITE flood with `inviteflood` to measure call processing resilience.
2. Test IAX2 flood with `iaxflood` against Asterisk servers.
3. Test RTP flood with `rtpflood` to disrupt active media streams.
4. Document flood thresholds that cause service degradation.

### Phase 6: Reporting

1. Document all discovered extensions, devices, and PBX configurations.
2. Record authentication weaknesses and cracked credentials.
3. Detail eavesdropping evidence with PCAP samples.
4. Report DoS thresholds and recovery behavior.
5. Provide remediation recommendations aligned with VoIP security best practices.

---

## Defense Perspective

Understanding VoIP attacks from the defender's viewpoint is essential for comprehensive penetration test reporting.

### SIP Hardening

- Enforce SIP TLS (port 5061) for all signaling traffic to prevent interception and tampering.
- Require strong digest authentication on all SIP methods (not just REGISTER — include INVITE, BYE, CANCEL).
- Implement fail2ban or equivalent rate-limiting on SIP registration attempts to slow credential brute-force.
- Use non-standard extension ranges and avoid predictable numbering schemes.
- Deploy SIP-aware firewalls or Session Border Controllers (SBCs) to filter malformed SIP messages.

### RTP Protection

- Enable SRTP (Secure RTP) with strong key exchange (DTLS-SRTP or SDES) for all media streams.
- Isolate voice traffic on dedicated VLANs with strict ACLs between voice and data segments.
- Monitor for anomalous RTP flows (unexpected endpoints, unusual bandwidth consumption).

### Network Segmentation

- Disable CDP/LLDP on user-facing switch ports to prevent VLAN hopping via voiphopper.
- Use dedicated voice VLAN ACLs that restrict access to authorized VoIP endpoints only.
- Implement 802.1X with MAB (MAC Authentication Bypass) for VoIP device onboarding.
- Disable unused trunk ports and restrict allowed VLANs on necessary trunks.

### Monitoring and Detection

- Deploy VoIP-aware IDS/IPS signatures for SIP scanning, flood attacks, and malformed messages.
- Monitor SIP registration rates and flag anomalies (high failure rates, rapid attempts from single IP).
- Log and alert on RTP sessions involving unauthorized endpoints.
- Use SIP honeypots to detect reconnaissance of VoIP infrastructure.

---

## Common Pitfalls

1. **Ignoring UDP Scanning**: SIP commonly runs over UDP. TCP-only port scans will miss SIP services. Always include UDP 5060/5061 in scans.
2. **Extension Range Assumptions**: PBX extensions vary widely. Start with broad ranges (100-9999) and narrow based on results rather than guessing.
3. **Rate Limiting Detection**: Aggressive enumeration triggers SIP rate-limiting and IP bans. Use throttling options (`-r` flags) and rotate source ports.
4. **NAT Traversal Complexity**: SIP devices behind NAT may use STUN/TURN. Direct testing may fail without understanding the network topology.
5. **Skipping RTP Encryption Check**: Assuming RTP is always unencrypted leads to false confidence. Verify SRTP is absent before claiming eavesdropping is possible.
6. **VoIP DoS Collateral Damage**: Flood attacks in shared infrastructure can impact non-target systems. Always scope DoS testing and obtain explicit authorization.
7. **Outdated Tool Versions**: SIPVicious tools have been rewritten (python3 version). Ensure you are using the correct version syntax for your Kali installation.
