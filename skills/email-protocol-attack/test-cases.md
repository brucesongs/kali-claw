# Email Protocol Attack Test Cases

> This file is a companion to `SKILL.md`, providing structured email protocol attack test case templates.
> Purpose: Check each item during penetration testing to ensure no critical email attack vectors are missed. Each case includes prerequisites, steps, expected results, and severity level.
> All tests are intended solely for authorized security assessments.

---

## Test Case Format

```
TC-EXXX | [Category] Test Name
Severity: CRITICAL / HIGH / MEDIUM / LOW
Prerequisites: Conditions that must be met before testing
Test Steps: Specific operations
Expected Results: Observable behavior when the vulnerability exists
Reference Payload: Corresponding section in payloads.md
```

---

## Index

- [A. SMTP Enumeration](#a-smtp-enumeration)
- [B. SMTP Relay](#b-smtp-relay)
- [C. Email Forgery](#c-email-forgery)
- [D. Authentication Bypass](#d-authentication-bypass)
- [E. Credential Attacks](#e-credential-attacks)
- [F. Exchange Exploitation](#f-exchange-exploitation)
- [G. TLS Testing](#g-tls-testing)
- [H. Header Manipulation](#h-header-manipulation)

---

## A. SMTP Enumeration

### TC-E001 | SMTP User Enumeration via VRFY/EXPN/RCPT TO

- **Severity**: HIGH
- **Objective**: Discover valid email accounts on the target mail server using SMTP enumeration commands
- **Prerequisites**: Network access to target mail server on SMTP port (25/587), list of potential usernames
- **Pre-condition**: Target mail server accepts SMTP connections and has not disabled VRFY/EXPN commands
- **Test Steps**:
  1. Connect to mail server: `nc mail.target.com 25`
  2. Test VRFY command: `VRFY admin`, `VRFY root`, `VRFY postmaster`
  3. Test EXPN command: `EXPN all-users`, `EXPN staff`
  4. Test RCPT TO enumeration: `MAIL FROM: test@test.com` then `RCPT TO: user@target.com`
  5. Run automated enumeration: `smtp-user-enum -M RCPT -U users.txt -t mail.target.com`
  6. Compare response codes between valid (250/252) and invalid (550/551) accounts
- **Expected Results**: Server responds with 250/252 for valid users and 550 for invalid users, revealing valid email accounts
- **Pass Criteria**:
  - [ ] At least one enumeration method (VRFY/EXPN/RCPT) returns distinguishable responses
  - [ ] Valid email accounts identified and documented
  - [ ] Enumeration method and response codes recorded
- **Remediation**: Disable VRFY and EXPN commands in mail server configuration; configure RCPT TO to return consistent responses regardless of recipient validity; implement rate limiting on SMTP connections
- **Reference**: payloads.md Section 1 SMTP User Enumeration

---

## B. SMTP Relay

### TC-E002 | SMTP Open Relay Detection

- **Severity**: CRITICAL
- **Objective**: Determine if the target mail server accepts and relays emails from unauthorized senders to external recipients
- **Prerequisites**: Network access to target mail server on SMTP port (25/465/587), external email address for receiving test emails
- **Pre-condition**: Target mail server is reachable and accepts SMTP connections
- **Test Steps**:
  1. Test basic relay: `swaks --to external@otherdomain.com --from test@target.com --server mail.target.com`
  2. Test fully external relay: `swaks --to victim@external.com --from attacker@evil.com --server mail.target.com`
  3. Test percent routing: `swaks --to "victim%external.com@target.com" --from test@test.com --server mail.target.com`
  4. Test source routing: `swaks --to "@target.com:victim@external.com" --from test@test.com --server mail.target.com`
  5. Test null sender relay: `(echo "HELO test.com"; echo "MAIL FROM: <>"; echo "RCPT TO: external@other.com"; echo "QUIT") | nc mail.target.com 25`
  6. Verify if test email arrives at external address
- **Expected Results**: Server accepts message with 250 OK response for external relay, and test email is delivered to the external address
- **Pass Criteria**:
  - [ ] At least one relay scenario accepted by the server
  - [ ] Test email received at external address
  - [ ] Relay method and affected configuration documented
  - [ ] Impact assessment includes spam and phishing risk
- **Remediation**: Configure mail server to require authentication for all outbound relay; restrict relay to authenticated users only; implement SPF and DKIM to prevent unauthorized use; block all relay routing tricks (percent, source, bang path)
- **Reference**: payloads.md Section 2 SMTP Open Relay Testing

---

## C. Email Forgery

### TC-E003 | Email Forgery and Sender Spoofing

- **Severity**: CRITICAL
- **Objective**: Test whether forged emails with spoofed sender addresses can be delivered to target recipients through the mail server
- **Prerequisites**: Network access to target mail server, knowledge of internal email addresses (from enumeration or OSINT)
- **Pre-condition**: Target email system does not reject emails from unauthorized senders or has weak authentication policies
- **Test Steps**:
  1. Spoof internal sender: `swaks --to victim@target.com --from ceo@target.com --server mail.target.com --header "Subject: Urgent"`
  2. Spoof external trusted domain: `swaks --to victim@target.com --from support@microsoft.com --server mail.target.com`
  3. Test display name spoof: `swaks --to victim@target.com --from "CEO Name <attacker@evil.com>"`
  4. Test reply-to redirection: `swaks --to victim@target.com --from admin@target.com --add-header "Reply-To: attacker@evil.com"`
  5. Verify forged email reaches recipient inbox (not spam/junk)
  6. Document which spoofing techniques bypass filters
- **Expected Results**: Forged email is delivered to the recipient's inbox without being flagged as spam or rejected, demonstrating successful sender spoofing
- **Pass Criteria**:
  - [ ] At least one spoofed email delivered to inbox
  - [ ] Spoofing technique that bypassed filters documented
  - [ ] Email authentication (SPF/DKIM/DMARC) result analyzed
  - [ ] Attack chain reproducible
- **Remediation**: Deploy and enforce SPF with `-all` policy; implement DKIM signing for all outgoing emails; configure DMARC with `p=reject` policy; train users to verify sender addresses; deploy email authentication awareness training
- **Reference**: payloads.md Section 3 Email Forgery with swaks

---

## D. Authentication Bypass

### TC-E004 | SPF Bypass Testing

- **Severity**: HIGH
- **Objective**: Identify weaknesses in the target domain's SPF configuration that allow unauthorized senders to send emails on behalf of the domain
- **Prerequisites**: DNS lookup capability, network access to target mail server
- **Pre-condition**: Target domain has an SPF record published in DNS
- **Test Steps**:
  1. Query SPF record: `dig TXT target.com +short | grep spf`
  2. Analyze SPF mechanism types: `+all`, `?all`, `~all`, `-all`
  3. Count DNS lookups in include chain (limit is 10)
  4. Test sending from IP not authorized in SPF: `swaks --to test@target.com --from spoofed@target.com --server mail.target.com`
  5. Test SPF softfail (~all) behavior — many servers still deliver softfail emails
  6. Test subdomain SPF (if no subdomain policy exists)
  7. Exploit include chain exceeding 10 DNS lookups (SPF evaluation fails open)
- **Expected Results**: SPF record uses `~all` (softfail) or `?all` (neutral) allowing spoofed emails through, or SPF include chain exceeds 10 lookups causing evaluation failure
- **Pass Criteria**:
  - [ ] SPF record retrieved and analyzed
  - [ ] Weakness identified (softfail, neutral, excessive includes, missing subdomain policy)
  - [ ] Spoofed email test confirms bypass
  - [ ] DNS lookup count in include chain calculated
- **Remediation**: Set SPF policy to `-all` (hard fail); reduce include chain to stay within 10 DNS lookup limit; publish SPF records for all subdomains; regularly audit SPF record for unauthorized IP ranges
- **Reference**: payloads.md Section 4 SPF/DKIM/DMARC Testing

### TC-E005 | DKIM Signature Testing

- **Severity**: HIGH
- **Objective**: Evaluate DKIM configuration for weaknesses including weak key lengths, exposed selectors, and signature verification bypass
- **Prerequisites**: DNS lookup capability, ability to send test emails to target domain
- **Pre-condition**: Target domain has DKIM configured (selectors published in DNS)
- **Test Steps**:
  1. Enumerate DKIM selectors: `dig TXT default._domainkey.target.com +short`
  2. Try common selectors: google, selector1, selector2, s1, k1, mail, policy
  3. Extract DKIM public key and check key length (512-bit is breakable, 1024-bit is weak, 2048-bit is minimum recommended)
  4. Check key length: `dig TXT selector._domainkey.target.com +short | grep -o "p=.*" | tr -d '"' | base64 -d | openssl rsa -pubin -text -noout`
  5. Send email without DKIM signature to test if receiver enforces DKIM verification
  6. Send email with tampered body content to test signature validation
- **Expected Results**: DKIM selector found with weak key (512-bit or 1024-bit RSA), or receiver accepts emails without valid DKIM signature
- **Pass Criteria**:
  - [ ] DKIM selector(s) enumerated and documented
  - [ ] Key length analyzed and weakness noted if applicable
  - [ ] Unsigned email delivery test completed
  - [ ] Tampered body signature validation test completed
- **Remediation**: Use minimum 2048-bit RSA or Ed25519 keys for DKIM; rotate DKIM keys regularly; configure receivers to enforce DMARC policy that rejects unsigned or invalid-signature emails; use unique non-obvious selector names
- **Reference**: payloads.md Section 4 SPF/DKIM/DMARC Testing

---

## E. Credential Attacks

### TC-E006 | IMAP/POP3 Credential Brute Force

- **Severity**: CRITICAL
- **Objective**: Test the resilience of IMAP/POP3 mail services against credential brute force and password spraying attacks
- **Prerequisites**: Network access to target IMAP (143/993) or POP3 (110/995) ports, list of potential usernames and passwords
- **Pre-condition**: Target mail server runs IMAP or POP3 services accessible from the testing network
- **Test Steps**:
  1. Identify IMAP/POP3 services: `nmap -sV -p 110,143,993,995 mail.target.com`
  2. Test single credentials manually: `openssl s_client -connect mail.target.com:993` then `a001 LOGIN user pass`
  3. Run brute force with hydra: `hydra -L users.txt -P passwords.txt mail.target.com imap`
  4. Run IMAPS brute force: `hydra -L users.txt -P passwords.txt mail.target.com imaps`
  5. Password spray with common passwords: `hydra -L users.txt -p "Welcome1!" mail.target.com imap`
  6. Test POP3: `hydra -L users.txt -P passwords.txt mail.target.com pop3`
  7. Verify valid credentials by accessing mailbox: `mutt -f imaps://user:pass@mail.target.com/INBOX`
- **Expected Results**: Valid credentials discovered allowing full mailbox access including reading emails, accessing contacts, and potentially manipulating forwarding rules
- **Pass Criteria**:
  - [ ] At least one valid credential pair discovered
  - [ ] Mailbox access confirmed with valid credentials
  - [ ] Account lockout policy tested and documented
  - [ ] Rate limiting behavior observed and recorded
- **Remediation**: Implement account lockout after failed login attempts; deploy rate limiting on IMAP/POP3 services; enforce strong password policies; enable multi-factor authentication for mail access; monitor for brute force patterns; consider IP-based access restrictions
- **Reference**: payloads.md Section 5 IMAP/POP3 Brute Force

---

## F. Exchange Exploitation

### TC-E007 | Exchange Server Exploitation

- **Severity**: CRITICAL
- **Objective**: Identify and exploit Microsoft Exchange server vulnerabilities including Autodiscover information disclosure, OWA weaknesses, and known CVEs
- **Prerequisites**: Network access to Exchange server endpoints (OWA, ECP, Autodiscover, EWS, ActiveSync), list of potential credentials
- **Pre-condition**: Target runs Microsoft Exchange Server with internet-facing web services
- **Test Steps**:
  1. Identify Exchange version via headers: `curl -s -I https://mail.target.com/owa/`
  2. Probe Autodiscover endpoint: `curl -s https://mail.target.com/Autodiscover/Autodiscover.xml`
  3. Test OWA authentication: `curl -s -I -u "domain\\user:password" https://mail.target.com/owa/`
  4. Probe ActiveSync: `curl -s -I https://mail.target.com/Microsoft-Server-ActiveSync`
  5. Test EWS access: `curl -s -I https://mail.target.com/EWS/Exchange.asmx`
  6. Check for known CVEs based on detected Exchange version (ProxyLogon CVE-2021-26855, ProxyShell CVE-2021-34473, etc.)
  7. Test credential brute force against OWA: `hydra -L users.txt -P passwords.txt mail.target.com https-post-form "/owa/auth/logon.aspx:username=^USER^&password=^PASS^:F=incorrect"`
  8. Enumerate internal URLs via Autodiscover response
- **Expected Results**: Exchange version identified, Autodiscover leaks internal hostnames and URLs, valid credentials obtained via brute force, or known CVE exploitable
- **Pass Criteria**:
  - [ ] Exchange version accurately identified
  - [ ] At least one endpoint probed (Autodiscover/OWA/EWS/ActiveSync)
  - [ ] Information disclosure documented (internal hostnames, URLs)
  - [ ] Known CVEs checked against detected version
  - [ ] Credential testing attempted and results recorded
- **Remediation**: Keep Exchange Server patched with latest security updates; disable legacy authentication (Basic Auth) in favor of Modern Auth; restrict Autodiscover access; implement conditional access policies; deploy MFA for all Exchange services; monitor for exploitation attempts in IIS logs
- **Reference**: payloads.md Section 6 Exchange Server Attacks

---

## G. TLS Testing

### TC-E008 | STARTTLS Downgrade and TLS Configuration Testing

- **Severity**: HIGH
- **Objective**: Assess mail server TLS configuration for weaknesses including protocol downgrade, weak cipher suites, expired certificates, and missing TLS enforcement
- **Prerequisites**: Network access to target mail server SMTP (25/465/587), IMAP (143/993), and POP3 (110/995) ports
- **Pre-condition**: Target mail server runs services with TLS/STARTTLS capability
- **Test Steps**:
  1. Test STARTTLS on SMTP: `openssl s_client -starttls smtp -connect mail.target.com:25 -showcerts`
  2. Check supported TLS versions: test TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3 individually
  3. Test for weak ciphers: `openssl s_client -starttls smtp -connect mail.target.com:25 -cipher EXPORT`
  4. Test for NULL cipher: `openssl s_client -starttls smtp -connect mail.target.com:25 -cipher NULL`
  5. Check certificate validity: `openssl s_client -starttls smtp -connect mail.target.com:25 2>/dev/null | openssl x509 -noout -dates -subject`
  6. Test IMAPS: `openssl s_client -connect mail.target.com:993 -showcerts`
  7. Test submission port TLS enforcement: attempt plaintext auth on port 587 without STARTTLS
  8. Run nmap cipher enumeration: `nmap --script ssl-enum-ciphers -p 465 mail.target.com`
  9. Test if STARTTLS can be stripped (downgrade scenario)
- **Expected Results**: Server supports deprecated TLS versions (1.0/1.1), accepts weak cipher suites (EXPORT, NULL, RC4), has expired or misconfigured certificate, or allows plaintext submission without TLS
- **Pass Criteria**:
  - [ ] TLS version support fully tested (1.0, 1.1, 1.2, 1.3)
  - [ ] Weak cipher suites tested and documented
  - [ ] Certificate validity and chain verified
  - [ ] STARTTLS downgrade resistance assessed
  - [ ] Plaintext submission allowed/not allowed confirmed
- **Remediation**: Disable TLS 1.0 and 1.1; configure strong cipher suites only (AES-GCM, ChaCha20); use certificates from trusted CA with proper chain; enforce TLS for all mail submission (port 587); implement MTA-STS and DANE for TLS enforcement between mail servers
- **Reference**: payloads.md Section 8 TLS/STARTTLS Testing

---

## Test Case Statistics

| Category | Cases | CRITICAL | HIGH | MEDIUM | LOW |
|----------|-------|----------|------|--------|-----|
| A. SMTP Enumeration | 1 | 0 | 1 | 0 | 0 |
| B. SMTP Relay | 1 | 1 | 0 | 0 | 0 |
| C. Email Forgery | 1 | 1 | 0 | 0 | 0 |
| D. Authentication Bypass | 2 | 0 | 2 | 0 | 0 |
| E. Credential Attacks | 1 | 1 | 0 | 0 | 0 |
| F. Exchange Exploitation | 1 | 1 | 0 | 0 | 0 |
| G. TLS Testing | 1 | 0 | 1 | 0 | 0 |
| **Total** | **8** | **4** | **4** | **0** | **0** |
