# Gobuster Advanced Features Guide

## Basic Syntax Review
```bash
gobuster dir -u http://target -w wordlist.txt
```

## Advanced Features

### 1. Multi-threading and Performance Optimization
```bash
# Set thread count (default 10)
gobuster dir -u http://target -w wordlist.txt -t 50

# Set request delay (avoid being blocked)
gobuster dir -u http://target -w wordlist.txt --delay 100ms

# Set timeout
gobuster dir -u http://target -w wordlist.txt --timeout 30s
```

### 2. Advanced Filtering Options
```bash
# Exclude specific status codes
gobuster dir -u http://target -w wordlist.txt -fc 404,500

# Show only specific status codes
gobuster dir -u http://target -w wordlist.txt -sc 200,301,302

# Filter based on response size
gobuster dir -u http://target -w wordlist.txt -fs 0,3456

# Filter based on response word count
gobuster dir -u http://target -w wordlist.txt -fw 123
```

### 3. Authentication and Session Management
```bash
# Basic authentication
gobuster dir -u http://target -w wordlist.txt -U username -P password

# Cookie support
gobuster dir -u http://target -w wordlist.txt -c "sessionid=abc123; auth=true"

# Custom Headers
gobuster dir -u http://target -w wordlist.txt -H "X-Forwarded-For: 127.0.0.1" -H "User-Agent: Custom"
```

### 4. File Extension Brute Force
```bash
# Brute force multiple file extensions
gobuster dir -u http://target -w wordlist.txt -x .php,.html,.js,.txt

# Recursive scanning
gobuster dir -u http://target -w wordlist.txt -r
```

### 5. DNS Subdomain Brute Force
```bash
# DNS mode
gobuster dns -d example.com -w subdomains.txt

# Use wildcard filtering
gobuster dns -d example.com -w subdomains.txt --wildcard
```

### 6. Practical Combination Techniques
```bash
# Combine multiple filter conditions
gobuster dir -u http://target -w wordlist.txt -sc 200,301,302 -fs 0,1234 -fw 10,20

# Output results to file
gobuster dir -u http://target -w wordlist.txt -o results.txt
```

## Practical Exercise Scenarios

### Scenario 1: Bypass Simple WAF
```bash
# Use random User-Agent
gobuster dir -u http://target -w wordlist.txt -H "User-Agent: $(curl -s https://httpbin.org/user-agent | jq -r .user_agent)"
```

### Scenario 2: API Endpoint Discovery
```bash
# Scanning for JSON API
gobuster dir -u http://api.target/v1 -w api-endpoints.txt -H "Accept: application/json" -H "Content-Type: application/json"
```

### Scenario 3: Admin Panel Discovery
```bash
# Common admin path scanning
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt -x .php,.asp,.aspx -sc 200,301,302
```