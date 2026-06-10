# IPSec VPN Enumeration and Fingerprinting Guide

## Introduction

IPSec VPN gateways expose IKE (Internet Key Exchange) services on UDP port 500 (and 4500 for NAT-T). Enumeration and fingerprinting of these services is the critical first step in any VPN security assessment. Unlike web applications, VPN services often run with minimal security monitoring, making them attractive targets for reconnaissance. This guide covers systematic enumeration and fingerprinting of IPSec VPNs to identify vendor, configuration, and potential vulnerabilities.

The IKE protocol operates in two phases: Phase 1 establishes a secure management channel, and Phase 2 negotiates the actual IPSec security associations for data transport. Understanding which Phase 1 mode the gateway supports (Main Mode vs Aggressive Mode) is crucial, as Aggressive Mode exposes the pre-shared key hash to offline cracking attacks.

**Objectives**: Master ike-scan for IKE enumeration, identify VPN vendors through fingerprinting, discover supported transforms, and assess VPN gateway security posture.

## IKE Protocol Overview

### IKE Phase 1

IKE Phase 1 establishes a secure channel using either:
- **Main Mode**: 6-message exchange, identity protected (recommended for security)
- **Aggressive Mode**: 3-message exchange, identity exposed (vulnerable to PSK capture)

Aggressive Mode is particularly dangerous because it transmits the peer identity and PSK hash in cleartext. Any network observer can capture the hash and attempt offline dictionary attacks. Despite this risk, many organizations still enable Aggressive Mode for compatibility with legacy clients or to simplify NAT traversal.

### Key Exchange Parameters

| Parameter | Values |
|-----------|--------|
| Encryption | DES(1), 3DES(5), AES-CBC(7), AES-CBC-256(13) |
| Hash | MD5(1), SHA1(2), SHA2-256(5) |
| DH Group | 1(768), 2(1024), 5(1536), 14(2048), 19(256-ECP), 20(384-ECP) |
| Auth | PSK(1), DSS(2), RSA(3) |

Weak algorithms such as DES, MD5, and DH groups 1-2 should be considered deprecated. Any gateway still accepting these transforms presents a clear vulnerability that should be documented in the assessment findings.

## Enumeration with ike-scan

### Basic Discovery

```bash
# Single target scan
ike-scan -M 192.168.1.1

# Subnet scan to discover all VPN gateways
ike-scan -M 192.168.1.0/24

# With showback (sends response back to verify connectivity)
ike-scan --showback -M 192.168.1.1

# Scan with custom source port to bypass ACLs
ike-scan --sport=500 -M 192.168.1.1
```

The `-M` flag enables multi-line display mode, which makes the output much easier to read by showing each SA attribute on a separate line. When scanning subnets, use the `--delay` option to avoid triggering rate-limiting or IDS systems.

### Transform Set Enumeration

```bash
# Test common transforms
ike-scan -M --trans='5,1,2,2' --trans='5,2,2,2' --trans='5,1,2,14' 192.168.1.1

# Test weak transforms that should be disabled
ike-scan -M --trans='1,1,1,1' --trans='1,2,1,1' 192.168.1.1

# IKEv2 scan (newer protocol version)
ike-scan -2 -M 192.168.1.1
```

Each transform is specified as `encryption,auth_method,hash,dh_group`. When a gateway responds to a transform proposal, it means that combination of encryption, hash, and DH group is accepted. Document all accepted transforms, paying special attention to any weak algorithms.

### Vendor Identification

IKE Vendor ID payloads reveal the VPN vendor and version. This information is critical for identifying known CVEs that may affect the target gateway.

```bash
# Capture vendor IDs
ike-scan -M --showback 192.168.1.1 | grep -i vid

# Common vendor IDs:
# Fortinet: 3e909d0c
# Cisco: 1f07f70e
# Juniper: 6a2ed524
# StrongSwan: 4048b7d56ebce88a
# Check Point: 810fa548
# WatchGuard: 80d0bbf4f4a16c2d
```

## Aggressive Mode Detection

```bash
# Test for aggressive mode vulnerability
ike-scan --aggressive --trans='5,1,2,2' -M 192.168.1.1

# If response includes ID and hash, aggressive mode is enabled
# The PSK hash can be extracted for offline cracking
ike-scan --aggressive --trans='5,1,2,2' -M 192.168.1.1 > psk_capture.txt

# Test with different identity types
ike-scan --aggressive --trans='5,1,2,2' --id="@vpn" -M 192.168.1.1
ike-scan --aggressive --trans='5,1,2,2' --id="192.168.1.100" -M 192.168.1.1
```

## Nmap VPN Scripts

```bash
# IKE version detection
nmap -sU -p 500 --script ike-version 192.168.1.1

# VPN service detection across common VPN ports
nmap -sU -p 500,4500,1701 --script vpn 192.168.1.1

# Full port scan for VPN services including SSL VPN
nmap -sS -sU -p 500,4500,1701,1723,443,1194,4433 -sV 192.168.1.1
```

## Hands-on Exercises

### Exercise 1: VPN Gateway Discovery

Scan a network range to discover all IPSec VPN gateways and document their IKE handshake behavior. Record which gateways respond, their handshake timing, and any vendor identification data visible in the initial response.

```bash
ike-scan -M 10.0.0.0/24 | grep "IKE"
```

### Exercise 2: Transform Set Mapping

Map all supported transform sets for a specific gateway by systematically testing each combination of encryption, hash, and DH group. This exercise helps build a complete picture of the gateway's cryptographic capabilities and identifies any weak algorithms that should be disabled.

```bash
for enc in 1 5 7 13; do
  for hash in 1 2 5; do
    for dh in 1 2 5 14; do
      result=$(ike-scan --trans="${enc},1,${hash},${dh}" 192.168.1.1 2>/dev/null)
      if echo "$result" | grep -q "SA"; then
        echo "ACCEPTED: enc=$enc hash=$hash dh=$dh"
      fi
    done
  done
done
```

### Exercise 3: Vendor Fingerprinting

Identify the VPN vendor by analyzing Vendor ID payloads and cross-referencing with known vendor signatures. Once the vendor is identified, research known CVEs for that specific platform.

```bash
ike-scan -M --showback 192.168.1.1 | grep -i "VID"
```

### Exercise 4: Aggressive Mode Assessment

Test if the VPN gateway supports aggressive mode and document the security risk, including whether the PSK hash can be captured. If aggressive mode is enabled, document the exact steps needed to capture and crack the PSK.

```bash
ike-scan --aggressive --trans='5,1,2,2' -M 192.168.1.1
```

## IKEv2 Specific Considerations

IKEv2 introduces several security improvements over IKEv1, including mutual authentication by default, simpler message exchange (4 messages instead of 6 for Main Mode), and built-in NAT traversal. However, IKEv2 gateways can still be vulnerable to configuration weaknesses.

When testing IKEv2 gateways, pay special attention to the supported authentication methods. While certificate-based authentication is recommended, many deployments still use PSK with IKEv2. The EAP (Extensible Authentication Protocol) methods supported by the gateway also affect security, with EAP-TLS being preferred over EAP-MSCHAPv2.

## Reporting Findings

When documenting IPSec VPN enumeration results, include the following for each discovered gateway: IP address, IKE version (v1/v2), accepted transform sets (highlighting any weak algorithms), vendor identification, aggressive mode status, and any captured PSK hashes. Prioritize findings based on the Common Vulnerability Scoring System (CVSS) and provide specific remediation recommendations.

## IKEv2 Specific Considerations

IKEv2 introduces several security improvements over IKEv1, including mutual authentication by default, simpler message exchange (4 messages instead of 6 for Main Mode), and built-in NAT traversal via encapsulation of ESP packets within UDP (RFC 5996 section 2.23). The IKEv2 protocol uses a SA_INIT exchange followed by an AUTH exchange, making it more resistant to DoS attacks through cookie-based puzzle mechanisms.

When testing IKEv2 gateways, pay special attention to the supported authentication methods. While certificate-based authentication (EAP-TLS) is recommended, many deployments still use PSK with IKEv2. The EAP methods supported by the gateway also affect security posture. EAP-TLS provides mutual certificate-based authentication and is the gold standard. EAP-MSCHAPv2, while convenient, is vulnerable to offline dictionary attacks if the IKE handshake can be captured. EAP-TTLS and PEAP provide a tunneled approach where an outer TLS session protects an inner authentication method.

IKEv2 also introduces the concept of IKE SA rekeying without disrupting existing IPsec SAs, which is a significant operational improvement. However, rekeying can be exploited for DoS if the gateway does not properly validate rekey requests. Test for rekey handling by initiating a connection and observing how the gateway behaves during SA lifetime expiration.

```bash
# IKEv2 transform enumeration
ike-scan -2 --trans='1,1,1,1' --trans='5,1,2,2' -M 192.168.1.1

# IKEv2 with EAP method detection
ike-scan -2 -M 192.168.1.1 | grep -i "eap\|auth"

# Test IKEv2 cookie mechanism (DoS protection)
ike-scan -2 --cookie -M 192.168.1.1
```

## Advanced Fingerprinting Techniques

Beyond basic Vendor ID matching, advanced fingerprinting techniques can identify the exact VPN gateway model and firmware version, enabling targeted vulnerability testing.

### Timing-Based Fingerprinting

Different VPN implementations respond to IKE packets with characteristic timing patterns. By measuring response times across multiple probe types, you can build a behavioral fingerprint that identifies the gateway even when Vendor IDs are stripped or spoofed.

```bash
# Measure response timing across multiple probes
for i in $(seq 1 10); do
  start_time=$(date +%s%N)
  ike-scan -M 192.168.1.1 2>/dev/null | grep -q "SA" && echo "Round $i: $(( ($(date +%s%N) - start_time) / 1000000 ))ms"
done

# Compare timing with known gateway profiles
# Cisco ASA: typically 30-100ms response time
# Fortinet FortiGate: typically 10-50ms
# strongSwan: typically 1-10ms (software-based)
# Palo Alto: typically 20-80ms
```

### Vendor-Specific Probe Patterns

```bash
# Fortinet-specific: test for FortiGate management interface
curl -k -s https://192.168.1.1/remote/login | grep -i "fortinet\|fortigate\|mrhyde\|fgt_lang"

# Cisco-specific: test for AnyConnect detection
curl -k -s https://192.168.1.1/+CSCOE+/logon.html | grep -i "anyconnect\|webvpn"

# Check Point-specific: test for Mobile Access portal
curl -k -s https://192.168.1.1/sslvpn/Login/Login.asp | grep -i "checkpoint\|ssl network extender"

# Juniper-specific: test for Pulse Secure / Juniper SA
curl -k -s https://192.168.1.1/dana-na/auth/url_default/welcome.cgi | grep -i "juniper\|pulse\|dana"
```

### Passive Fingerprinting

When active scanning is too risky, passive observation of VPN traffic can reveal information about the gateway implementation. ESP packet sizes, IKE retry behavior, and DH group preferences all leak information about the underlying VPN stack.

```bash
# Passive capture and analysis of IKE negotiation patterns
tcpdump -i any -w passive_ike.pcap 'udp port 500 or udp port 4500' -c 100

# Analyze captured IKE packets for vendor patterns
tshark -r passive_ike.pcap -Y "isakmp" -T fields \
  -e ip.src -e ip.dst -e isakmp.type -e isakmp.dh_group \
  -e isakmg.encryption_algorithm -e isakmp.hash_algorithm 2>/dev/null

# Extract and decode Vendor ID payloads from passive captures
tshark -r passive_ike.pcap -Y "isakmp.type == 0" -T fields \
  -e data.data 2>/dev/null | sort -u
```

## Reporting Findings

When documenting IPSec VPN enumeration results, include the following for each discovered gateway: IP address, IKE version (v1/v2), accepted transform sets (highlighting any weak algorithms), vendor identification, aggressive mode status, and any captured PSK hashes. Prioritize findings based on the Common Vulnerability Scoring System (CVSS) and provide specific remediation recommendations.

### Finding Categories

1. **CRITICAL**: Aggressive mode enabled with weak PSK. Expired or self-signed certificates. PPTP protocol supported.
2. **HIGH**: Weak encryption algorithms accepted (DES, 3DES, MD5). Default or weak PSK values. Missing multi-factor authentication.
3. **MEDIUM**: IKEv1 still enabled alongside IKEv2. Split tunneling allowed without restrictions. Long IKE SA lifetimes (24+ hours).
4. **LOW**: Information disclosure through Vendor ID payloads. Non-standard IKE port configurations. Missing dead peer detection.

### Report Template

```markdown
## VPN Gateway Assessment: [IP Address]

### Gateway Information
- **IP**: [IP Address]
- **Vendor**: [Identified vendor and version]
- **IKE Version**: [v1, v2, or both]
- **Protocols**: [IPSec, SSL VPN, PPTP, L2TP]

### Accepted Transform Sets
| Encryption | Hash | DH Group | Authentication |
|------------|------|----------|----------------|
| [value]    | [value] | [value] | [value] |

### Security Issues
1. [Issue description] — Severity: [CRITICAL/HIGH/MEDIUM/LOW]
   - Impact: [description]
   - Remediation: [specific fix]
```

## References

- RFC 7296 — IKEv2 specification
- RFC 2409 — IKEv1 specification
- ike-scan documentation — https://github.com/royhills/ike-scan
- Nmap VPN scripts — https://nmap.org/nsedoc/scripts/ike-version.html
- VPN security assessment methodology — OWASP Testing Guide
- VPN Penetration Testing Guide — PTES Technical Guidelines
- IPSec VPN Security Assessment — NIST SP 800-77
- RFC 5996 — IKEv2 improvements and clarification
- VPN Fingerprinting Techniques — SANS Reading Room
