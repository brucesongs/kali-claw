# FFUF Advanced Features Guide

## Basic Syntax Review
```bash
ffuf -u http://target/FUZZ -w wordlist.txt
```

## Advanced Features

### 1. Multi-Variable Fuzzing
```bash
# Multiple FUZZ positions
ffuf -u http://target/FUZZ1/FUZZ2 -w wordlist1.txt:FUZZ1,wordlist2.txt:FUZZ2

# Nested wordlists
ffuf -u http://target/FUZZ -w wordlist.txt -w extensions.txt:EXT -mc all -H "Content-Type: application/EXT"
```

### 2. Advanced Matching and Filtering
```bash
# Match specific status codes
ffuf -u http://target/FUZZ -w wordlist.txt -mc 200,301,302

# Exclude status codes
ffuf -u http://target/FUZZ -w wordlist.txt -fc 404,403

# Match based on response size
ffuf -u http://target/FUZZ -w wordlist.txt -ms 1234

# Match based on response word count
ffuf -u http://target/FUZZ -w wordlist.txt -mw 56

# Regex matching
ffuf -u http://target/FUZZ -w wordlist.txt -mr "admin|dashboard|login"
```

### 3. Request Customization
```bash
# Custom Headers
ffuf -u http://target/FUZZ -w wordlist.txt -H "X-Forwarded-For: 127.0.0.1" -H "Authorization: Bearer token"

# POST request
ffuf -u http://target/login -w passwords.txt -X POST -d "username=admin&password=FUZZ" -H "Content-Type: application/x-www-form-urlencoded"

# JSON POST
ffuf -u http://target/api -w wordlist.txt -X POST -d '{"param":"FUZZ"}' -H "Content-Type: application/json"
```

### 4. Performance and Rate Control
```bash
# Thread control
ffuf -u http://target/FUZZ -w wordlist.txt -t 100

# Rate limiting (requests per second)
ffuf -u http://target/FUZZ -w wordlist.txt -p 0.1

# Auto-calibration
ffuf -u http://target/FUZZ -w wordlist.txt -ac
```

### 5. Output and Result Processing
```bash
# Multiple output formats
ffuf -u http://target/FUZZ -w wordlist.txt -o results.json -of json
ffuf -u http://target/FUZZ -w wordlist.txt -o results.csv -of csv

# Real-time output
ffuf -u http://target/FUZZ -w wordlist.txt -v
```

### 6. Advanced Techniques

#### Conditional Fuzzing
```bash
# Conditional testing based on previous results
ffuf -u http://target/FUZZ -w wordlist.txt -mc 200 | while read line; do
    ffuf -u "$line/admin" -w admin-paths.txt -mc 200
done
```

#### Encoding Handling
```bash
# URL encoding
ffuf -u http://target/FUZZ -w wordlist.txt -enc

# Base64 encoding
echo -n "FUZZ" | base64 | ffuf -u http://target/$(cat) -w wordlist.txt
```

## Practical Exercise Scenarios

### Scenario 1: Path Traversal Detection
```bash
ffuf -u http://target/download?file=FUZZ -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -mc 200 -mr "root:"
```

### Scenario 2: API Parameter Brute Force
```bash
ffuf -u http://api.target/v1/users -w user-ids.txt:UID -H "Authorization: Bearer FUZZ" -mc 200 -w tokens.txt:FUZZ
```

### Scenario 3: Virtual Host Discovery
```bash
ffuf -u http://target -w subdomains.txt -H "Host: FUZZ.target.com" -mc 200,301,302
```

### Scenario 4: File Upload Bypass
```bash
ffuf -u http://target/upload -w extensions.txt:EXT -X POST -F "file=@test.EXT" -mc 200
```