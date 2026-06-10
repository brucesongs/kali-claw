# SMTP Enumeration and Relay Testing Guide

> Complete guide for SMTP reconnaissance: user enumeration, open relay detection, banner fingerprinting, and mail server version detection.
> All techniques are for authorized penetration testing only.

---

## Introduction and Objective

SMTP (Simple Mail Transfer Protocol) is the backbone of internet email delivery, operating on port 25 (relay), 465 (SMTPS), and 587 (submission). Originally designed in 1982 for a trusted academic network, SMTP lacks built-in authentication and encryption in its base specification. These design decisions created persistent attack surfaces that remain exploitable decades later.

This guide covers the full SMTP reconnaissance pipeline:

1. **Server discovery** -- Finding mail servers via DNS MX records and port scanning
2. **Banner grabbing and fingerprinting** -- Identifying mail server software and version
3. **User enumeration** -- Discovering valid email accounts via VRFY, EXPN, and RCPT TO
4. **Open relay testing** -- Determining if the server forwards unauthorized mail
5. **EHLO capability analysis** -- Mapping supported SMTP extensions and security features

By the end of this guide, you will be able to perform comprehensive SMTP reconnaissance as part of a mail infrastructure security assessment, identify misconfigurations that expose user accounts or enable spam relay, and provide actionable remediation recommendations.

### Tools Covered

| Tool | Primary Use | Installation |
|------|-------------|--------------|
| smtp-user-enum | Automated user enumeration | Pre-installed on Kali |
| swaks | SMTP Swiss Army Knife | `apt install swaks` |
| smtpmap | Server fingerprinting | Pre-installed on Kali |
| nmap | Service detection and NSE scripts | Pre-installed on Kali |
| openssl | TLS/STARTTLS testing | Pre-installed on Kali |
| dig/host | DNS MX record lookup | Pre-installed on Kali |

---

## Hands-on Exercises

### Exercise 1: Mail Server Discovery via DNS

Before interacting with any SMTP server, you must identify which hosts handle mail for the target domain. DNS MX (Mail Exchange) records specify the mail servers responsible for accepting email for a domain.

```bash
# Query MX records for the target domain
dig MX target.com +short

# Query with additional details (TTL, priority)
dig MX target.com

# Use alternative DNS tools
host -t MX target.com

# Query via specific DNS server
dig MX target.com @8.8.8.8 +short

# Resolve MX record hostnames to IP addresses
dig MX target.com +short | awk '{print $2}' | while read mx; do
  echo "$mx: $(dig +short $mx A) $(dig +short $mx AAAA)"
done
```

MX records return a priority value (lower = preferred) and the mail server hostname. A domain with multiple MX records has backup mail servers. Each MX hostname should be resolved to its IP address for direct interaction.

After identifying mail server hostnames, scan for all mail-related ports to discover additional services:

```bash
# Full mail service port scan with version detection
nmap -sV -p 25,110,143,465,587,993,995,2525,3389 target.com

# Scan all MX servers
for mx in $(dig MX target.com +short | awk '{print $2}'); do
  echo "[*] Scanning $mx..."
  nmap -sV -p 25,110,143,465,587,993,995 $mx
done
```

### Exercise 2: SMTP Banner Grabbing and Fingerprinting

SMTP servers typically announce themselves via a greeting banner when a client connects. This banner often reveals the server software, version, and hostname.

```bash
# Basic banner grab via netcat
nc mail.target.com 25

# Save banner for analysis
nc -w 5 mail.target.com 25 > smtp_banner.txt 2>&1

# Banner grab with timeout
timeout 5 nc mail.target.com 25
```

Common banner patterns and their meanings:

- `220 mail.target.com ESMTP Postfix (Ubuntu)` -- Postfix on Ubuntu
- `220 mail.target.com Microsoft ESMTP MAIL Service ready` -- Microsoft Exchange
- `220 mail.target.com ESMTP Sendmail 8.15.2/8.15.2` -- Sendmail with version
- `220 mail.target.com ESMTP Exim 4.94.2` -- Exim with version

Use smtpmap for automated fingerprinting that goes beyond the banner:

```bash
# Basic fingerprinting
smtpmap mail.target.com

# With verbose output showing detection confidence
smtpmap mail.target.com -v

# Test submission port
smtpmap mail.target.com -p 587
```

The EHLO command reveals supported SMTP extensions, which provide valuable intelligence about server capabilities:

```bash
# Request extended capabilities
(echo "EHLO test.com"; sleep 2) | nc mail.target.com 25

# Compare with basic HELO (fewer capabilities returned)
(echo "HELO test.com"; sleep 2) | nc mail.target.com 25
```

Key capabilities to look for:

- `STARTTLS` -- TLS upgrade support
- `AUTH LOGIN PLAIN` -- Authentication mechanisms available
- `SIZE 10485760` -- Maximum message size
- `VRFY` -- User verification enabled (information disclosure)
- `EXPN` -- Mailing list expansion enabled (information disclosure)
- `HELP` -- Help command available
- `ETRN` -- Extended turn (queue processing)
- `8BITMIME` -- 8-bit data support
- `DSN` -- Delivery Status Notifications

### Exercise 3: User Enumeration with smtp-user-enum

SMTP user enumeration leverages three commands that mail servers may expose:

**VRFY (Verify)** -- Asks the server to verify if a username exists. Returns 252 (exists) or 550 (does not exist).

```bash
# Manual VRFY testing
echo "VRFY admin" | nc mail.target.com 25
echo "VRFY root" | nc mail.target.com 25
echo "VRFY postmaster" | nc mail.target.com 25
echo "VRFY nonexistentuser12345" | nc mail.target.com 25
```

**EXPN (Expand)** -- Asks the server to expand a mailing list into its members. Returns the list of subscribers.

```bash
# Manual EXPN testing
echo "EXPN all" | nc mail.target.com 25
echo "EXPN staff" | nc mail.target.com 25
echo "EXPN admin" | nc mail.target.com 25
```

**RCPT TO (Recipient)** -- The most reliable method. After issuing MAIL FROM, you test RCPT TO with various addresses. The server responds differently for valid vs invalid recipients even when VRFY/EXPN are disabled.

```bash
# Manual RCPT TO enumeration
(echo "HELO test.com"
echo "MAIL FROM: test@test.com"
echo "RCPT TO: admin@target.com"
echo "RCPT TO: nonexistent9999@target.com"
echo "QUIT") | nc mail.target.com 25
```

Automated enumeration with smtp-user-enum is significantly more efficient:

```bash
# VRFY method (fastest, but often disabled)
smtp-user-enum -M VRFY -U /usr/share/wordlists/usernames.txt -t mail.target.com

# RCPT TO method (most reliable, works even when VRFY is disabled)
smtp-user-enum -M RCPT -U /usr/share/wordlists/usernames.txt -t mail.target.com

# EXPN method (for mailing list discovery)
smtp-user-enum -M EXPN -U /usr/share/wordlists/usernames.txt -t mail.target.com

# Custom wordlist with domain suffix
smtp-user-enum -M RCPT -U users.txt -t mail.target.com -f admin@test.com

# Multiple targets
for target in mail1.target.com mail2.target.com; do
  echo "[*] Enumerating $target..."
  smtp-user-enum -M RCPT -U users.txt -t $target
done
```

When analyzing results, categorize SMTP response codes:

- `252` -- Cannot VRFY user, but will accept message (user likely exists)
- `250` -- User verified (definitely exists)
- `550` -- User unknown (definitely does not exist)
- `551` -- User not local (forwarding information may be provided)
- `502` -- Command not implemented (VRFY/EXPN disabled)

### Exercise 4: Open Relay Testing

An open relay is a mail server that accepts and forwards email from any sender to any recipient without authentication. Open relays are heavily abused for spam, phishing, and email bombing.

```bash
# Test 1: Basic external relay
swaks --to external@gmail.com --from test@target.com --server mail.target.com

# Test 2: Fully external sender to external recipient
swaks --to external@gmail.com --from attacker@evil.com --server mail.target.com

# Test 3: Percent routing relay
swaks --to "victim%external.com@target.com" --from test@test.com --server mail.target.com

# Test 4: Source routing
swaks --to "@target.com:victim@external.com" --from test@test.com --server mail.target.com

# Test 5: Bang path routing (legacy)
swaks --to "target.com!external.com!victim" --from test@test.com --server mail.target.com

# Test 6: Null sender
(echo "HELO test.com"; echo "MAIL FROM: <>"; echo "RCPT TO: external@other.com"; echo "DATA"; echo "Subject: Test"; echo ""; echo "Test"; echo "."; echo "QUIT") | nc mail.target.com 25
```

Use nmap for automated relay testing:

```bash
# nmap SMTP open relay script
nmap --script smtp-open-relay -p 25 mail.target.com

# With custom recipient for verification
nmap --script smtp-open-relay --script-args smtp-open-relay.to=external@gmail.com -p 25 mail.target.com
```

### Exercise 5: Combining Reconnaissance into a Full Assessment

This exercise ties together all previous techniques into a comprehensive SMTP assessment workflow:

```bash
#!/bin/bash
# Full SMTP Assessment Script
TARGET_DOMAIN=$1
MAIL_SERVER=$2

echo "=========================================="
echo "SMTP Security Assessment: $TARGET_DOMAIN"
echo "Mail Server: $MAIL_SERVER"
echo "=========================================="

echo ""
echo "[Phase 1] DNS Mail Infrastructure"
echo "-----------------------------------"
echo "MX Records:"
dig MX $TARGET_DOMAIN +short
echo ""
echo "SPF Record:"
dig TXT $TARGET_DOMAIN +short | grep spf
echo ""

echo "[Phase 2] Port Scan"
echo "-----------------------------------"
nmap -sV -p 25,110,143,465,587,993,995 $MAIL_SERVER

echo ""
echo "[Phase 3] Banner and Fingerprint"
echo "-----------------------------------"
echo "SMTP Banner:"
timeout 5 nc $MAIL_SERVER 25 2>&1 | head -1
echo ""
echo "EHLO Capabilities:"
(echo "EHLO assess.com"; sleep 2) | nc $MAIL_SERVER 25 2>/dev/null

echo ""
echo "[Phase 4] User Enumeration"
echo "-----------------------------------"
smtp-user-enum -M RCPT -U /usr/share/wordlists/usernames.txt -t $MAIL_SERVER 2>/dev/null

echo ""
echo "[Phase 5] Open Relay Test"
echo "-----------------------------------"
nmap --script smtp-open-relay -p 25 $MAIL_SERVER

echo ""
echo "[Phase 6] TLS Configuration"
echo "-----------------------------------"
openssl s_client -starttls smtp -connect $MAIL_SERVER:25 -showcerts 2>/dev/null | openssl x509 -noout -dates -subject -issuer 2>/dev/null

echo ""
echo "=========================================="
echo "Assessment Complete"
echo "=========================================="
```

---

## References and Resources

### RFC Documents

- **RFC 5321** -- Simple Mail Transfer Protocol (the SMTP specification)
  - https://tools.ietf.org/html/rfc5321
- **RFC 3207** -- SMTP Service Extension for Secure SMTP over Transport Layer Security
  - https://tools.ietf.org/html/rfc3207
- **RFC 4954** -- SMTP Service Extension for Authentication
  - https://tools.ietf.org/html/rfc4954
- **RFC 7208** -- Sender Policy Framework (SPF) for Authorizing Use of Domains in Email
  - https://tools.ietf.org/html/rfc7208

### Tools Documentation

- **smtp-user-enum** -- SMTP user enumeration tool manual
  - `man smtp-user-enum` or `smtp-user-enum --help`
- **swaks** -- Swiss Army Knife for SMTP documentation
  - https://github.com/jetmore/swaks
  - `swaks --help` for comprehensive usage guide
- **nmap NSE Scripts** -- SMTP-related scripts
  - https://nmap.org/nsedoc/scripts/smtp-commands.html
  - https://nmap.org/nsedoc/scripts/smtp-open-relay.html
  - https://nmap.org/nsedoc/scripts/smtp-enum-users.html

### Learning Resources

- **HackTricks - Pentesting SMTP**
  - https://book.hacktricks.xyz/pentesting/pentesting-smtp
- **OWASP Testing Guide - Testing for SMTP Weakness**
  - https://owasp.org/www-project-web-security-testing-guide/
- **PortSwigger - Email Vulnerabilities**
  - https://portswigger.net/web-security/email
- **MXToolbox** -- Online mail server diagnostic tools
  - https://mxtoolbox.com/
