# Responsible Disclosure Workflow Guide

> Guide for the security-bounty-hunter skill — covers the complete responsible disclosure process from initial vendor contact through CVE assignment, timeline management, and public advisory publication.

## Overview

Responsible disclosure is the process of privately reporting security vulnerabilities to vendors and coordinating a fix before public disclosure. This is not just ethics — it is strategy. A well-executed disclosure process builds reputation, establishes relationships with vendors, and in many cases is legally required to qualify for safe harbor protections.

This guide covers the full disclosure lifecycle: finding the right contact, reporting effectively, managing timelines, requesting CVEs, and publishing advisories.

---

## Vendor Contact Process

### Step 1: Check for Established Security Channels

Before any outreach, check for existing security reporting mechanisms:

**Priority order for finding contact channels:**

| Priority | Channel | How to Check |
|----------|---------|-------------|
| 1 | Bug bounty platform (HackerOne, Bugcrowd, etc.) | Search platform for the vendor's program |
| 2 | SECURITY.md in repository root | `https://github.com/org/repo/blob/main/SECURITY.md` |
| 3 | security.txt | `https://target.com/.well-known/security.txt` |
| 4 | GitHub Security Advisories | `https://github.com/org/repo/security/advisories` |
| 5 | Security email (security@vendor.com) | Check for published PGP key |
| 6 | General support or CTO email | Last resort, use professional tone |

### Step 2: GitHub Security Advisory (Preferred for Open Source)

For open-source projects on GitHub, private vulnerability reporting is the best channel:

1. Navigate to the repository's Security tab
2. Click "Report a vulnerability"
3. Fill in the advisory form with:
   - Summary (one-line description)
   - Description (detailed technical explanation)
   - Affected versions
   - Severity (CVSS score if known)
   - Proof of concept

**Advantages:**
- Private channel, not visible to the public
- Built-in CVE request mechanism
- Maintainers are notified immediately
- Timeline tracking is built in

### Step 3: Direct Email Contact

When no formal channel exists:

```
Subject: [Security Advisory] [Vulnerability Type] in [Product/Component]

Dear Security Team,

I have discovered a security vulnerability in [Product] that I would like
to report responsibly.

Summary: [One-line description]
Severity: [Critical/High/Medium/Low]
Affected Versions: [version range]

I have a proof of concept and detailed technical analysis ready to share.
Could you please confirm this email reaches the appropriate security team?

I am committed to responsible disclosure and will coordinate with you on
a disclosure timeline.

Best regards,
[Your name/handle]
```

**Email security considerations:**
- If the vendor publishes a PGP key, encrypt your email
- Do not include the full PoC in the initial email
- Confirm the recipient before sharing sensitive details
- Keep a record of all communications

### Step 4: Escalation Path

If the vendor is unresponsive:

| Timeline | Action |
|----------|--------|
| Day 0 | Initial report via primary channel |
| Day 7 | Follow-up via same channel |
| Day 14 | Second follow-up, try alternate channel |
| Day 30 | Third follow-up, consider CERT/CC |
| Day 45 | Contact CERT/CC or national CSIRT |
| Day 90 | Public disclosure (with or without vendor fix) |

### CERT/CC Escalation

When the vendor is unresponsive after 30+ days:

1. Submit to US-CERT: https://www.kb.cert.org/vuls/report/
2. Contact relevant national CSIRT if non-US vendor
3. Include: product details, vulnerability description, timeline of contact attempts
4. CERT/CC will attempt to contact the vendor on your behalf

---

## CVE Request Workflow

### Path 1: GitHub Security Advisory (Easiest)

For open-source projects with GitHub advisories:

1. Create a private security advisory on the repository
2. In the advisory, click "Request CVE"
3. GitHub (as a CNA) will assign a CVE ID
4. Timeline: typically 1-3 business days
5. The CVE is published when the advisory is made public

### Path 2: MITRE CVE Request

For non-GitHub projects:

1. Submit request at https://cveform.mitre.org/
2. Select "Request a CVE ID"
3. Provide required information:

| Field | Description |
|-------|-------------|
| Product | Name and URL of affected product |
| Version | Affected version range |
| Vulnerability type | CWE classification |
| Impact | What an attacker can achieve |
| Attack vector | How the vulnerability is triggered |
| Reporter | Your name/handle (or anonymous) |
| Public references | Any existing public discussion |

4. Timeline: typically 1-7 business days for assignment
5. You receive a CVE ID (CVE-YYYY-NNNNN format)

### Path 3: Vendor CNA

Many large vendors are their own CVE Numbering Authority:

| Vendor | CNA Portal |
|--------|-----------|
| Microsoft | MSRC CVE portal |
| Apple | Apple Security portal |
| Google | Google VRP / bug hunters |
| Oracle | Oracle Security Alerts |
| Apache | Apache Security team |
| Red Hat | Bugzilla security flag |

Check the full CNA list: https://www.cve.org/PartnerInformation/ListofPartners

### Required Information for CVE Request

Regardless of the path, prepare:

```markdown
## CVE Request Information

**Product**: [Product name and URL]
**Vendor**: [Vendor name]
**Affected Versions**: [e.g., < 2.5.3, all versions before 2026-01-15]
**Vulnerability Type**: [CWE-XXX]
**Attack Vector**: [Network/Local/Physical]
**Authentication Required**: [None/Single/Multiple]
**User Interaction**: [None/Required]
**Impact**: [Confidentiality/Integrity/Availability impact]
**CVSS 3.1 Score**: [calculated score]
**Proof of Concept**: [available on request or included]
**Public Disclosure Date**: [planned date or "coordinated with vendor"]
```

---

## Timeline Management

### Standard Disclosure Timeline

The industry-standard responsible disclosure timeline is 90 days:

```
Day 0:    Report submitted to vendor
Day 7:    Vendor acknowledges receipt
Day 14:   Vendor confirms vulnerability
Day 30:   Vendor provides fix timeline
Day 60:   Vendor develops and tests fix
Day 90:   Public disclosure (if fix is ready)
```

### Accelerated Timeline (Actively Exploited)

When the vulnerability is being actively exploited in the wild:

```
Day 0:    Report submitted to vendor (mark as URGENT)
Day 1:    Vendor acknowledges and begins emergency response
Day 7:    Vendor releases emergency patch or mitigation
Day 14-30: Public disclosure with details
```

Criteria for accelerated disclosure:
- Evidence of active exploitation in the wild
- Vulnerability affects a large number of users
- No workaround or mitigation available
- Public safety at risk (medical devices, infrastructure, etc.)

### Extended Timeline (Complex Fixes)

When the fix requires significant development effort:

```
Day 0:     Report submitted to vendor
Day 14:    Vendor confirms, estimates fix timeline
Day 30:    Vendor requests extension with justification
Day 60:    Checkpoint on fix progress
Day 90:    Standard deadline, discuss further extension if needed
Day 120:   Vendor releases fix
Day 180:   Maximum extension, public disclosure regardless
```

Extension criteria (mutual agreement):
- Fix requires architectural changes
- Multiple affected products or versions
- Vendor demonstrates good-faith progress
- No active exploitation evidence

### Milestone Checklist

| Milestone | Action Items |
|-----------|-------------|
| **Day 0** | Submit report, record all details, set calendar reminders |
| **Day 7** | Follow up if no acknowledgment, try alternate channels |
| **Day 30** | Confirm vendor is working on fix, discuss timeline |
| **Day 60** | Check fix progress, request beta/test patch if available |
| **Day 90** | Coordinate public disclosure, prepare advisory |

---

## Report Template

### Advisory Header

```markdown
# [CVE-YYYY-NNNNN] [Vulnerability Type] in [Product Name]

**Advisory ID**: [CVE-YYYY-NNNNN or pending]
**Severity**: [Critical/High/Medium/Low] (CVSS [score])
**Affected Versions**: [version range]
**Fixed Versions**: [version or commit hash]
**Publication Date**: [YYYY-MM-DD]
**Discoverer**: [Your name/handle]
```

### Technical Description

```markdown
## Technical Description

[Product Name] version [affected versions] contains a [vulnerability type]
in the [component/module] component. The vulnerability exists because
[root cause description].

When [trigger condition], an attacker can [exploit description] by
[attack method]. This allows [impact description].

### Root Cause

[Detailed explanation of why the vulnerability exists, referencing specific
code paths or logic flaws. Include file paths and line numbers if applicable.]

### Attack Prerequisites

- [Prerequisite 1, e.g., Network access to the web application]
- [Prerequisite 2, e.g., Valid user account (or none required)]
- [Prerequisite 3, e.g., Target user must visit a crafted URL]
```

### Proof of Concept

```markdown
## Proof of Concept

### Environment
- **Product Version**: [version]
- **Operating System**: [OS and version]
- **Configuration**: [relevant config, e.g., default installation]

### Steps to Reproduce

1. [Step 1: Setup or precondition]
2. [Step 2: Trigger action]
3. [Step 3: Observe result]

### PoC Request/Script

[Sanitized request or script — remove any real hostnames, credentials,
or sensitive data. Use example.com or similar placeholders.]

[Include expected response showing the vulnerability]
```

### Impact Assessment

```markdown
## Impact

### Direct Impact
- [What the attacker can directly achieve]

### Business Impact
- [Real-world consequences for users and the vendor]

### Attack Scenario
[Describe a realistic attack scenario demonstrating how this vulnerability
could be exploited in practice]

### CVSS 3.1 Score

**Vector**: CVSS:3.1/AV:[N|A|L|P]/AC:[L|H]/PR:[N|L|H]/UI:[N|R]/S:[U|C]/C:[H|L|N]/I:[H|L|N]/A:[H|L|N]
**Base Score**: [score]
**Severity**: [Critical/High/Medium/Low]
```

### Remediation Guidance

```markdown
## Remediation

### Immediate Mitigation
- [Short-term workaround users can apply immediately]

### Permanent Fix
- [Update to version X.Y.Z or later]
- [Apply patch from commit/PR reference]

### Vendor Recommendations
- [Additional hardening steps the vendor should consider]

### Upgrade Path
[Clear instructions for users to upgrade or apply the fix]
```

### Credits and Timeline

```markdown
## Credits

- **Discovered by**: [Your name/handle]
- **Reported**: [YYYY-MM-DD]
- **Vendor notified**: [YYYY-MM-DD]
- **Vendor confirmed**: [YYYY-MM-DD]
- **Fix released**: [YYYY-MM-DD]
- **Advisory published**: [YYYY-MM-DD]

## Timeline

| Date | Event |
|------|-------|
| YYYY-MM-DD | Vulnerability discovered |
| YYYY-MM-DD | Vendor notified via [channel] |
| YYYY-MM-DD | Vendor acknowledged |
| YYYY-MM-DD | Vendor confirmed vulnerability |
| YYYY-MM-DD | Fix developed and tested |
| YYYY-MM-DD | Fix released |
| YYYY-MM-DD | Advisory published |
```

---

## Legal Considerations

### Before Testing

1. **Check local laws**: Computer fraud and abuse laws vary by jurisdiction. Understand what is legal in your location and the vendor's location.
2. **Scope authorization**: Only test within the declared scope of a bug bounty program or with explicit written permission.
3. **Document authorization**: Keep records of scope declarations, program rules, and any explicit permission received.

### During Testing

1. **Avoid accessing other users' data**: If you accidentally access another user's data, stop immediately, document what you saw, and report it.
2. **Do not modify data**: Read-only testing. Do not delete, modify, or corrupt any data.
3. **Minimize impact**: Use the least invasive techniques possible. A proof of concept should demonstrate the issue, not cause damage.
4. **Safe payloads**: Use benign payloads (e.g., `id`, `whoami` for RCE; your own test account for IDOR).

### Safe Harbor Provisions

Many jurisdictions and platforms provide safe harbor for good-faith security research:

- **US**: CFAA does not apply to good-faith security research (recent DOJ guidance)
- **EU**: Various national laws protect security researchers
- **Bug bounty platforms**: Platform terms typically include safe harbor provisions
- **Vendor policies**: Many vendors explicitly authorize security research in their policies

**Safe harbor typically requires:**
- Testing within declared scope
- Good-faith effort to avoid harm
- Responsible disclosure (private report first)
- No public disclosure before vendor has time to fix

### NDA Considerations

For private bug bounty programs:

1. **Read the NDA carefully**: Understand what you can and cannot disclose publicly
2. **Disclosure restrictions**: Private programs may prohibit any public discussion of findings
3. **Portfolio references**: Some NDAs allow referencing the program in your portfolio with approval
4. **Duration**: Note when the NDA expires — some are time-limited

---

## Communication Best Practices

### Professional Tone

All communications with vendors should be:
- **Professional**: No boastful language or ultimatums
- **Clear**: Technical precision without unnecessary complexity
- **Respectful**: Acknowledge the vendor's effort and constraints
- **Patient**: Vendors have competing priorities; reasonable timelines benefit everyone
- **Persistent**: Do not let reports go stale — follow up regularly

### Report Quality Checklist

Before submitting any report:

- [ ] Title is concise and descriptive (e.g., "SQL Injection in User Search API")
- [ ] Vulnerable component is precisely identified (endpoint, file, line)
- [ ] Proof of concept is minimal, safe, and reproducible
- [ ] Impact is clearly stated with business context
- [ ] Affected version/environment is specified
- [ ] Remediation suggestion is actionable and specific
- [ ] Evidence includes full request/response (sanitized)
- [ ] CVSS score is calculated and justified

### Handling Vendor Responses

| Vendor Response | Your Action |
|----------------|-------------|
| Acknowledged, working on fix | Wait patiently, follow up per timeline |
| "Not a security issue" | Provide additional evidence, explain impact more clearly |
| "Duplicate" | Ask for the original report ID if not provided |
| "Informative" (not bounty-worthy) | Accept gracefully, document for future learning |
| "Out of scope" | Verify against scope policy, dispute if warranted with evidence |
| No response | Follow escalation path in timeline |
| Dispute on severity | Provide additional impact evidence, reference program definitions |

### Follow-up Templates

**7-day follow-up:**

```
Subject: Re: [Security Advisory] [Vulnerability Type] in [Product]

Hi [Security Team],

Following up on my report submitted on [date]. Has your team had a
chance to review it? I'm happy to provide any additional information
or clarify any details.

Looking forward to your response.
```

**30-day follow-up:**

```
Subject: Re: [Security Advisory] [Vulnerability Type] in [Product] - 30-day update

Hi [Security Team],

It has been 30 days since my initial report on [date]. I wanted to
check on the status and understand the timeline for a fix.

I remain committed to responsible disclosure and am happy to work
with you on coordinating the disclosure timeline.

Per responsible disclosure best practices, I plan to publish the
advisory 90 days from the initial report date ([date]), or sooner
if a fix is available.

Please let me know if you need any additional information.
```

---

## Integration with Other Skills

| Skill | Integration Point |
|-------|------------------|
| `article-writing` | Advisory drafting, CVSS scoring, report formatting |
| `knowledge-ops` | Tracking disclosure timelines across sessions |
| `autonomous-loops` | Watch Loop for monitoring vendor responses and fix progress |
| `osint` | Finding vendor security contacts and responsible parties |
| `deep-research` | Researching similar vulnerabilities and existing CVEs |
