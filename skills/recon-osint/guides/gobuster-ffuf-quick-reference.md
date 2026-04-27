# Security Tools Quick Reference Card

## Gobuster Core Commands
```bash
# Basic directory brute force
gobuster dir -u URL -w WORDLIST

# Advanced filtering
gobuster dir -u URL -w WORDLIST -sc 200,301 -fc 404 -fs SIZE -fw WORDS

# DNS subdomain brute force  
gobuster dns -d DOMAIN -w WORDLIST

# Authentication support
gobuster dir -u URL -w WORDLIST -U USER -P PASS -c "COOKIE"
```

## FFUF Core Commands
```bash
# Basic fuzzing
ffuf -u URL/FUZZ -w WORDLIST

# Multi-variable testing
ffuf -u URL/FUZZ1/FUZZ2 -w LIST1:FUZZ1,LIST2:FUZZ2

# Advanced matching
ffuf -u URL/FUZZ -w WORDLIST -mc 200 -ms SIZE -mw WORDS -mr "REGEX"

# POST request
ffuf -u URL -X POST -d "param=FUZZ" -w WORDLIST
```

## WPScan Core Commands
```bash
# Basic scan
wpscan --url URL

# Enumerate components
wpscan --url URL --enumerate vp,ap,at,u

# Brute force
wpscan --url URL --password-attack wp-login -U USER -P WORDLIST

# Detailed output
wpscan --url URL --output FILE --format json
```

## Common Wordlist Locations
- Kali Linux: `/usr/share/wordlists/`
- SecLists: `/usr/share/seclists/`
- Custom: `./wordlists/`

## Security Best Practices
1. **Always obtain authorization** - Only test within authorized scope
2. **Use local environments** - Prefer locally deployed test targets
3. **Control rate** - Avoid performance impact on targets
4. **Record results** - Save scan results for analysis
5. **Comply with laws** - Understand and comply with relevant laws and regulations