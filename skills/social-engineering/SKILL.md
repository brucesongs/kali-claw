---
name: social-engineering
description: "Social engineering is the art of exploiting human psychological weaknesses rather than technical vulnerabilities to execute attacks. Attack vectors encompass Phishing, Pretexting, Baiting, Tailgating, Vishing, and other techniques."
origin: openclaw
version: "0.2.0.2"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
metadata:
  domain: social
  tool_count: 6
  guide_count: 5
  mitre: "TA0043-Reconnaissance"
  last_reviewed: "2026-07-21"
---




# Skill: Social Engineering

> **Supplementary Files**:
> - `payloads.md` — SE attack payloads organized by category: phishing, email spoofing, credential harvesting, smishing, vishing, USB baiting, OSINT profiling, physical social engineering
> - `test-cases.md` — Structured test cases with severity levels covering phishing campaigns, email security, credential harvesting, physical/voice social engineering, and defense testing

## Summary

Attack vectors encompass Phishing, Pretexting, Baiting, Tailgating, Vishing, and other techniques.

**Tools**: SET (setoolkit), GoPhish, King-Phisher, Maltego, theHarvester, recon-ng

**Domain**: social

**MITRE ATT&CK**: TA0043-Reconnaissance

## Description

Social engineering is the art of exploiting human psychological weaknesses rather than technical vulnerabilities to execute attacks. Attack vectors encompass Phishing, Pretexting, Baiting, Tailgating, Vishing, and other techniques. Technical defenses can be patched, but human trust, curiosity, and instinct to obey authority represent a permanent attack surface — **Human is the weakest link**.

This skill covers the complete social engineering attack chain from target profiling, pretext development, attack vector selection, to credential/action harvesting, combined with OSINT tools for precise, customized attacks. Mastered tools include SET (Social-Engineer Toolkit), GoPhish, King-Phisher, Maltego, theHarvester, and recon-ng.

---

## Use Cases

1. **Enterprise Security Awareness Assessment** - Test employee security awareness through authorized phishing exercises, generating quantified reports
2. **Red Team Social Engineering Simulation** - Simulate real APT attacker social engineering techniques to assess organizational defense capabilities
3. **Credential Harvesting Testing** - Build simulated login pages to test whether users will submit real credentials
4. **Physical Security Testing** - Assess physical access control effectiveness through Tailgating and Pretexting
5. **OSINT Target Profiling** - Collect target personnel social media, email, and organizational structure information to support precise social engineering

---

## Core Tools

| Tool | Purpose | Command/Usage Example |
|------|---------|----------------------|
| **SET (setoolkit)** | Integrated social engineering attack framework, phishing/website cloning/payloads | `sudo setoolkit` -> select attack vector |
| **GoPhish** | Web-managed phishing campaign platform | Dashboard to create Campaign + Landing Page |
| **King-Phisher** | Phishing campaign management and awareness training | `king-phisher` GUI + server-side deployment |
| **Maltego** | Visual OSINT correlation analysis and target profiling | Domain -> Email -> Social Profile transformation chains |
| **theHarvester** | Automated email/subdomain/hostname collection | `theHarvester -d target.com -b all` |
| **recon-ng** | Modular web reconnaissance framework, automated OSINT | `recon-ng` -> `use recon/domains-contacts/` |

---

## Methodology

### Attack Chain

```
Target              Pretext             Attack Vector       Delivery            Harvest &
Reconnaissance  ->  Development     ->  Selection       ->  Execution       ->  Analysis
(OSINT Profiling)   (Pretext Dev)       (Vector Select)     (Delivery)          (Harvest)
    |                   |                  |                  |                   |
    v                   v                  v                  v                   v
theHarvester       Scenario           Phishing           Email/SMS/         Credential
Maltego            construction       Baiting            USB/file delivery  collection
recon-ng           Identity           Vishing            Phone/in-person    Behavior
LinkedIn/          impersonation      Tailgating         Physical approach  analysis
social media       Script design                                             Report
mining             Timing selection                                          generation &
                                                                             iteration
```

**Phase Details**:

1. **Target Reconnaissance** - Collect target personnel information through OSINT: email addresses, job roles, social media activity, organizational structure, and technology stack preferences. The more precise the information, the higher the social engineering credibility.
2. **Pretext Development** - Build convincing attack scenarios based on reconnaissance results: IT department password reset notifications, HR benefits surveys, package delivery notices, executive urgent directives. Pretexts must align with the target's daily work scenarios.
3. **Attack Vector Selection** - Choose the optimal attack method based on target characteristics: email phishing for technical users, voice social engineering for non-technical users, tailgating or USB baiting for physical scenarios.
4. **Payload Delivery** - Execute the attack: send phishing emails, make phone calls, deploy USB devices, make in-person contact. Control the pace to avoid triggering alerts from simultaneous mass engagement.
5. **Credential & Action Harvest** - Collect credentials submitted on phishing pages, record target click behaviors, analyze interaction timelines and response patterns.

### Defense Perspective

| Defense Measure | Description | Attack Type Countered |
|-----------------|-------------|----------------------|
| **Security Awareness Training** | Regular security awareness training and phishing exercises | Phishing / Spear Phishing |
| **Email Filtering (SPF/DKIM/DMARC)** | Email authentication and content filtering | Email spoofing / phishing delivery |
| **MFA (Multi-Factor Auth)** | Add a second authentication factor beyond passwords | Post-credential-theft abuse |
| **Verification Procedures** | Secondary confirmation and callback verification for sensitive operations | Pretexting / Vishing |
| **Physical Access Control** | Access cards + biometric authentication + visitor registration | Tailgating / physical intrusion |
| **USB Port Policy** | Disable or restrict unauthorized USB devices | Baiting / malicious USB delivery |

---

## Practical Steps

> **Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.**

### 1. SET Phishing Campaign

```bash
# Launch SET (requires root privileges)
sudo setoolkit

# Select Social-Engineering Attacks (1)
# -> Spear-Phishing Attack Vectors (1)
# -> Perform a Mass Email Attack (1)

# Select Payload (e.g., Arduino / Meterpreter)
# Select email template or customize
# Configure target email list and SMTP server
```

### 2. Email Spoofing Techniques

```bash
# Use sendemail to send phishing emails with spoofed sender
sendemail -f "IT-Support@target-company.com" \
  -t victim@target-company.com \
  -u "Urgent: Password Expiration Notice" \
  -m "Your email password will expire in 24 hours. Please update immediately: http://evil-server/reset" \
  -s smtp.evil-server.com:587 \
  -xu username -xp password \
  -o tls=yes

# SPF/DKIM/DMARC detection (pre-attack reconnaissance)
dig txt target-company.com | grep -i spf
dig txt _dmarc.target-company.com
```

### 3. GoPhish Credential Harvesting Page

```
# GoPhish standard workflow:
# 1. Landing Pages - Clone target login page, add credential capture
# 2. Email Templates - Design phishing email template
# 3. Sending Profiles - Configure SMTP sending channel
# 4. Users & Groups - Import target email list
# 5. Campaigns - Launch campaign and monitor in real-time

# RESTful API automation example:
curl -X POST https://gophish-server/api/campaigns/ \
  -H "Authorization: {api_key}" \
  -d '{"name":"Q2-Phishing-Test","template":1,"page":1,"smtp":1,"groups":[1]}'
```

### 4. Pretexting Scenario Design

```
Common high-success-rate pretext scenarios:
- IT Help Desk password reset (impersonate IT support, claim abnormal login detected)
- HR benefits survey (impersonate HR sending survey link that actually collects credentials)
- Executive urgent directive (impersonate C-Level requiring finance/assistant to execute urgent operations)
- Package/delivery notification (forge package pickup link to induce clicks)
- Tech support callback (Vishing: impersonate Microsoft/Google support requesting remote access)
```

### 5. OSINT Target Profiling Workflow

```bash
# Step 1: Domain -> Email collection
theHarvester -d target-company.com -b all -l 500

# Step 2: Social media cross-validation
# LinkedIn: job title, department, tech stack, hire date
# Twitter/X: technical interests, recent activities, tools used
# GitHub: open-source projects, technical preferences, information leaked in code

# Step 3: Maltego visual correlation
# Domain -> DNS Names -> IP Address -> AS Number
# Domain -> Email -> Person -> Social Profile -> Phone Number

# Step 4: recon-ng automated aggregation
recon-ng
> marketplace install all
> modules load recon/domains-contacts/email-harvester
> options set source target-company.com
> run
```

## Detection Methods

Detecting social engineering threats requires monitoring multiple communication channels simultaneously. Email header analysis (SPF, DKIM, DMARC pass/fail) identifies spoofed senders before users interact with malicious content. URL inspection tools reveal lookalike domains and credential harvesting pages. On the human side, tracking unusual request patterns — such as employees suddenly requesting sensitive data access or password resets outside normal procedures — helps identify active pretexting campaigns targeting the organization.

### Email Gateway Indicators
- **Authentication failures**: SPF `SoftFail` / `Permerror`, DKIM `fail` / `neutral`, DMARC `quarantine` / `reject` verdicts.
- **Lookalike domains**: Homoglyph attacks (`аpple.com` Cyrillic `а`), `reply-` prefixes, punycode (`xn--` IDN), recently registered sender domains (<30 days).
- **Header anomalies**: `Reply-To` differs from `From`; `Received` chain shows unusual hops; `X-Originating-IP` from bulletproof hosting.
- **Attachment patterns**: Password-protected archives with password in email body; `.iso`/`.img`/`.vhd` container files (Mark-of-the-Web bypass); LNK files with embedded PowerShell.

### Web / Credential Harvesting Indicators
- **Lookalike TLS**: Recently issued Let's Encrypt certs for `secure-login-*` domains; typosquatted SAN entries.
- **Modlishka / Evilginx patterns**: Reverse proxy traffic to legitimate IdP (Okta/Azure AD); user-agent anomalies (bot-like JS execution).
- **Newly registered domains**: Domains registered <7 days ago; `cdn-` / `login-` / `auth-` prefixed domains mimicking target's brand.
- **Form action URLs**: Login forms POSTing to non-corporate domains; form `action` attribute changed via JavaScript after page load.

### Behavioral / Human Indicators
- **Off-hours requests**: Executives requesting wire transfers or sensitive data outside business hours (BEC pattern).
- **Urgency cues**: Emails with phrases like "ASAP", "urgent wire transfer", "ceo request"; pressure to bypass normal procedures.
- **Geo-anomalies**: VPN logins from new country/region followed by sensitive data access.
- **Reporting cadence**: Spike in user-reported phishing emails indicates either a campaign or improved training — correlate with click rates.

### SIEM Detection Rules
- **Splunk SPL**: `index=email sourcetype=mailscanner action=reject | stats count by sender_domain | sort -count`
- **Sigma rule**: `sigma/rules/email/bec_pattern.yml` — detects CEO fraud patterns.
- **Microsoft 365 ATP**: Anti-phishing policies with mailbox intelligence; first-contact safety tip for external senders.
- **SOAR playbooks**: Auto-disable user account after click on known-bad URL; force password reset + MFA re-enrollment.

## Defense Evasion Techniques

### Email Bypass Techniques
- **Bypass SPF/DMARC via legitimate relay**: Compromise an account on a trusted relay (e.g., Mailchimp, SendGrid, Microsoft 365 tenant) to inherit reputation.
- **Reply-To mismatch exploitation**: Use `From: ceo@company.com` (SPF fails) but `Reply-To: ceo@attacker.com` — many clients show only From.
- **Display name abuse**: `From: "CEO Name" <attacker@external.com>` — mobile clients hide the email address.
- **Unicode homoglyphs**: `аpple.com` (Cyrillic а), `microsоft.com` (Cyrillic о), `bnа.com` (Cyrillic а).
- **Punycode confusion**: `xn--80ak6aa92e.com` renders as `аррӏе.com` (Apple lookalike).
- **Thread hijacking**: Compromise one party, then reply to an existing legitimate thread to insert malicious link (high trust).

### Web / Credential Theft Evasion
- **Reverse proxy phishing (Modlishka, Evilginx, Muraena)**: Proxy real IdP login; capture credentials AND session cookies in real-time; bypasses MFA.
- **Cloudflare Workers abuse**: Host phishing page on `*.workers.dev` to inherit Cloudflare reputation.
- **Blob URLs**: Use `URL.createObjectURL()` to serve malicious JS without persistent URL (evades scanners).
- **Open redirect chains**: Chain 3+ open redirects to obfuscate final destination.
- **Brand logo SVG theft**: Use real SVG logos to evade image-comparison detection.
- **JS cloaking**: Show benign content to security scanners (User-Agent, IP-based) but phishing page to real users.

### Pretext Engineering
- **Vendor impersonation**: Impersonate a known vendor (e.g.,CrowdStrike, Microsoft support) — trust transferred from legitimate brand.
- **Internal team spoofing**: Impersonate IT support / HR / Legal — use shared document pretexts ("Q4 salary review", "compliance training").
- **MFA fatigue + helpdesk social**: Trigger MFA fatigue, then call helpdesk claiming lost phone to reset MFA.
- **Callback bypass**: Some organizations require callback verification — pre-text as target's manager to authorize.
- **AI voice cloning**: Use ElevenLabs / Resemble to clone CEO voice for vishing calls ($243K deepfake CEO scam in 2024).
- **Deepfake video**: Real-time deepfake for video calls (2024 Arup engineer case — $25M loss).

### Delivery Stealth
- **SMS over email**: SMS open rate 98% vs email 20%; use SMS for credential theft links.
- **QR codes (Quishing)**: Embed phishing URL in QR code (bypasses email URL scanners; user opens on personal phone).
- **Multipart attachments**: Hide payload in `multipart/related` MIME structure; some scanners only inspect first part.
- **Password-protected archive**: Use `.zip` with password "2024" shared in email body — bypasses AV signature scanning.
- **Steganography**: Hide payload URL in image LSB; user extracted via "view image" reveals the link.

### Persistence & Lateral Movement
- **OAuth consent phishing**: Trick user into granting OAuth app consent (persistent access without credentials).
- **Session token theft over credentials**: Steal session cookies via reverse proxy; use them past MFA re-enrollment.
- **Email rule creation**: Create hidden inbox rule (`pm-sent` folder) to hide replies from user's view.
- **Forwarding rule**: Auto-forward sensitive emails to external address via legitimate email rule.

### Tracking Evasion
- **Pixel blocking**: Use CSS-only "view" tracking (no pixel image); evade email client image-blocking.
- **Unique URLs per recipient**: Generate unique URL per email to identify which recipient clicked (don't reuse).
- **Time-decay links**: URL valid only for 30 min after send; evades delayed sandbox detonation.
- **Geo-fenced links**: URL only returns phishing page if accessed from target company's IP range.

---

## Reporting

Social engineering assessment reports must quantify organizational risk with measurable metrics. Key metrics include click-through rate (percentage of targets who clicked phishing links), credential submission rate (percentage who entered credentials on harvesting pages), and time-to-report (how quickly targets reported the suspicious communication to security teams). Each finding should include the pretext scenario, delivery method, target demographics, and specific behavioral observations that inform training recommendations.

## Common Pitfalls

A frequent mistake in social engineering assessments is using generic, low-effort phishing templates that test spam filter effectiveness rather than employee awareness. Effective assessments use realistic, context-specific pretexts that mirror actual threats targeting the organization's industry. Another pitfall is neglecting the post-compromise phase — after credentials are harvested, the assessment should demonstrate the actual business impact (access to sensitive systems, data exfiltration potential) to justify remediation investment.

---

## Hacker Laws

1. **The Weakest Link Is Human** - Firewalls can be perfectly configured, VPNs can encrypt all traffic, but a well-crafted phishing email can bypass all technical defenses. The essence of social engineering is shifting the attack surface from technical systems to people — and people can never be patched.

2. **Trust but Verify** - Pretexting succeeds because targets blindly trust authority. The defender's countermeasure: any request involving credentials, money, or sensitive data must be verified through an independent channel. The attacker's insight: anticipate and neutralize verification behaviors within the pretext.

3. **First Principles Thinking** - Don't mechanically copy social engineering templates. Understand the psychological mechanisms of trust-building (authority, urgency, social proof, reciprocity), and design attack schemes from first principles for specific targets. Generic phishing emails are noise; customized Spear Phishing is the weapon.

---

## Learning Resources

  **This skill's supplementary files**: payloads.md, test-cases.md

  **Related skills**: skills/recon-osint/SKILL.md, skills/social-intelligence/SKILL.md, skills/deep-research/SKILL.md, skills/web-xss/SKILL.md

  **External resources**:
  - **SET Official Repository**: [github.com/trustedsec/social-engineer-toolkit](https://github.com/trustedsec/social-engineer-toolkit)
  - **GoPhish Official Documentation**: [getgophish.com/documentation](https://getgophish.com/documentation/)
  - **Social-Engineer.org**: [social-engineer.org](https://www.social-engineer.org/) - Social engineering framework and attack vector encyclopedia
  - **Kevin Mitnick - The Art of Deception**: Classic social engineering book for understanding the psychological foundations of trust exploitation
  - **HackTricks - Phishing**: [book.hacktricks.xyz/generic-methodologies-and-resources/phishing](https://book.hacktricks.xyz/generic-methodologies-and-resources/phishing)
  - **King-Phisher**: [github.com/securestate/king-phisher](https://github.com/securestate/king-phisher)
