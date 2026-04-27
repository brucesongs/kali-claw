# WPScan Learning Guide

## Basic Command Syntax

### 1. Basic Scanning
```bash
# Scan WordPress version and basic information
wpscan --url http://target.com

# Disable TLS checks (for self-signed certificates)
wpscan --url https://target.com --disable-tls-checks
```

### 2. Plugin Enumeration
```bash
# Enumerate all plugins
wpscan --url http://target.com --enumerate p

# Enumerate vulnerable plugins
wpscan --url http://target.com --enumerate vp

# Enumerate a specific number of plugins
wpscan --url http://target.com --enumerate p --plugins-detection mixed
```

### 3. Theme Enumeration
```bash
# Enumerate themes
wpscan --url http://target.com --enumerate t

# Enumerate vulnerable themes
wpscan --url http://target.com --enumerate vt
```

### 4. User Enumeration
```bash
# Enumerate users
wpscan --url http://target.com --enumerate u

# Enumerate a specific range of user IDs
wpscan --url http://target.com --enumerate u --users-range 1-10
```

### 5. Password Brute Force
```bash
# Brute force using username list and password wordlist
wpscan --url http://target.com --usernames admin,user --passwords /path/to/wordlist.txt

# Read usernames from file
wpscan --url http://target.com --usernames /path/to/usernames.txt --passwords /path/to/passwords.txt
```

### 6. Advanced Options
```bash
# Set request timeout
wpscan --url http://target.com --request-timeout 30

# Set thread count
wpscan --url http://target.com --threads 5

# Use proxy
wpscan --url http://target.com --proxy http://127.0.0.1:8080

# Output to file
wpscan --url http://target.com --output-file scan_results.json --format json
```

## Typical Use Cases

### Scenario 1: Quick Information Gathering
```bash
wpscan --url http://target.com --enumerate p,t,u
```

### Scenario 2: Vulnerability Assessment
```bash
wpscan --url http://target.com --enumerate vp,vt --plugins-version-detection aggressive
```

### Scenario 3: Credential Testing
```bash
wpscan --url http://target.com --usernames admin --passwords /usr/share/wordlists/rockyou.txt
```

## Notes

1. **Legality**: Only use within authorized scope
2. **Rate Limiting**: Avoid causing DoS to the target
3. **Update Database**: Regularly update the vulnerability database
   ```bash
   wpscan --update
   ```
4. **Error Handling**: Handle network timeouts and connection errors

## Output Explanation

- **[+]**: Discovered information
- **[i]**: General information
- **[!]**: Warning or potential issue
- **[ERROR]**: Error message

## Troubleshooting

### Common Errors
1. **"does not seem to be running WordPress"**: Target is not a WordPress site
2. **SSL/TLS errors**: Use `--disable-tls-checks` option
3. **Connection timeouts**: Increase `--request-timeout` value
4. **Rate limiting**: Reduce `--threads` count

### Environment Requirements
- Ruby 2.6+
- Bundler
- Internet connection (for database updates)

## Learning Progress

- **Theoretical learning**: Complete
- **Hands-on practice**: Requires real WordPress environment
- **Command mastery**: Complete
- **Advanced features**: Pending practice

---
**Last Updated**: 2026-03-19
**Learning Status**: Theory mastery, pending practice verification
