# WPScan Advanced Features Guide

## Basic Syntax Review
```bash
wpscan --url http://wordpress-target
```

## Advanced Features

### 1. Scan Scope Control
```bash
# Scan only WordPress core version
wpscan --url http://target --enumerate vp

# Scan plugins
wpscan --url http://target --enumerate ap

# Scan themes
wpscan --url http://target --enumerate at

# Scan users
wpscan --url http://target --enumerate u

# Combined scan
wpscan --url http://target --enumerate vp,ap,at,u
```

### 2. Brute Force Features
```bash
# Username brute force
wpscan --url http://target --password-attack wp-login -U admin -P /usr/share/wordlists/rockyou.txt

# Multi-user brute force
wpscan --url http://target --password-attack xmlrpc -U users.txt -P passwords.txt

# XML-RPC brute force (more stealthy)
wpscan --url http://target --password-attack xmlrpc -U admin -P wordlist.txt
```

### 3. Authentication and Session Management
```bash
# Use Cookie
wpscan --url http://target --cookie "wordpress_logged_in=abc123"

# Use Token
wpscan --url http://target --api-token YOUR_API_TOKEN

# Custom User-Agent
wpscan --url http://target --user-agent "Custom Scanner"
```

### 4. Advanced Enumeration Options
```bash
# Limit plugin scan count
wpscan --url http://target --enumerate ap --plugins-detection mixed --plugins-version-threshold 5

# Detailed theme enumeration
wpscan --url http://target --enumerate at --themes-detection aggressive

# Media file enumeration
wpscan --url http://target --enumerate m
```

### 5. Output and Reports
```bash
# JSON output
wpscan --url http://target --output results.json --format json

# CLI output to file
wpscan --url http://target --output results.txt

# Verbosity control
wpscan --url http://target --verbose
```

### 6. Performance and Evasion
```bash
# Request delay
wpscan --url http://target --random-user-agent --delay 2

# Proxy settings
wpscan --url http://target --proxy http://127.0.0.1:8080

# Timeout settings
wpscan --url http://target --request-timeout 30 --connect-timeout 15
```

## Practical Exercise Scenarios

### Scenario 1: Plugin Vulnerability Detection
```bash
# Scan for known vulnerable plugins
wpscan --url http://target --enumerate ap --plugins-detection aggressive --plugins-version-all
```

### Scenario 2: Misconfiguration Detection
```bash
# Detect debug mode and config file leaks
wpscan --url http://target --enumerate tt,cb,dbe
```

### Scenario 3: Admin Path Discovery
```bash
# Discover non-standard wp-admin paths
wpscan --url http://target --enumerate p --wp-content-dir custom-content
```

### Scenario 4: Multi-Site Scanning
```bash
# Batch scan multiple WordPress sites
cat sites.txt | xargs -I {} wpscan --url {} --enumerate vp,ap --output {}.json --format json
```

## Security Notes

1. **Legal Authorization**: Ensure you have permission to scan the target website
2. **Rate Limiting**: Avoid causing DoS impact on the target
3. **API Token**: Register for WPScan API Token for better vulnerability database access
4. **Local Testing**: Prefer practicing in local WordPress environments

## Local Test Environment Setup

```bash
# Use Docker to quickly set up WordPress test environment
docker run --name wordpress-test -p 8080:80 -d wordpress:latest
```