# Web Application Security Command Line Tools Detailed Reference

## 1. Nikto - Webservicestoolsecurity scanner

### Basic Usage
```bash
# Basic scan
nikto -h target.com

# Specify port and SSL
nikto -h https://target.com:443

# Use proxy
nikto -h target.com -useproxy http://proxy:8080

# Specify output file
nikto -h target.com -o report.txt -Format txt
```

### Advanced Options
```bash
# Scan specific CGI directories
nikto -h target.com -Cgidirs /cgi-bin/,/scripts/

# Add custom HTTP headers
nikto -h target.com -Add-header "X-Forwarded-For: 127.0.0.1"

# Virtual host scanning
nikto -h target.com -vhost admin.target.com

# Timeout settings
nikto -h target.com -timeout 30

# Ignore specific response codes
nikto -h target.com -404code 302,301
```

### Scan Types
- **0**: File upload vulnerabilities
- **a**: Authentication bypass
- **b**: Software identification
- **c**: Remote file inclusion
- **d**: Web services
- **e**: Admin consoles

### Practical Points
- Slow scan speed but broad coverage
- Contains 6700+ potentially dangerous files/programs
- Supports SSL and virtual hosts
- Configurable proxy and timeout

## 2. Dirb - directory brute force tool

### Basic Usage
```bash
# Basic directory brute force
dirb http://target.com

# Use custom wordlist
dirb http://target.com /usr/share/wordlists/dirb/common.txt

# Multiple wordlist files
dirb http://target.com wordlist1.txt,wordlist2.txt

# Recursive scanning
dirb http://target.com -r
```

### Advanced Options
```bash
# Authentication
dirb http://target.com -u username:password

# customHTTPheaders
dirb http://target.com -H "User-Agent: Custom"

# Proxy settings
dirb http://target.com -p http://proxy:8080

# Extension brute force
dirb http://target.com -X .php,.html,.js

# Save session
dirb http://target.com -o session_file
```

### Practical Points
- Focused on directory and file discovery
- Supports recursive scanning
- Can handle authentication and custom headers
- Sessions can be resumed, suitable for large-scale scanning

## 3. Gobuster - Directory/Subdomain/DNS Brute Force Tool

### Basic Usage
```bash
# Directory brute force
gobuster dir -u http://target.com -w wordlist.txt

# Subdomain brute force
gobuster dns -d target.com -w subdomains.txt

# Virtual host brute force
gobuster vhost -u http://target.com -w vhosts.txt

# Fuzzing
gobuster fuzz -u http://target.com/FUZZ -w wordlist.txt
```

### Advanced Options
```bash
# Authentication
gobuster dir -u http://target.com -w wordlist.txt -U user -P pass

# customHTTPheaders
gobuster dir -u http://target.com -w wordlist.txt -H "X-Forwarded-For: 127.0.0.1"

# Proxy settings
gobuster dir -u http://target.com -w wordlist.txt -p http://proxy:8080

# filteringresults
gobuster dir -u http://target.com -w wordlist.txt -fc 404,500 -fs 0

# Recursive scanning
gobuster dir -u http://target.com -w wordlist.txt -r
```

### Output Options
- `-o output.txt`: Save results to file
- `-x extensions`: add extensions（such as.php,.html）
- `-t threads`: set thread count（default10）
- `-z`: Don't show progress

### Practical Points
- Fast, supports multi-threading
- Supports multiple brute force modes (dir, dns, vhost, fuzz)
- Flexible result filtering
- Supports recursive and extension brute force

## 4. FFUF - Fuzzing Tool

### Basic Usage
```bash
# Basic fuzzing
ffuf -u http://target.com/FUZZ -w wordlist.txt

# Multi-variable fuzzing
ffuf -u http://target.com/FUZZ/PATH -w words.txt:FUZZ -w paths.txt:PATH

# HTTP header fuzzing
ffuf -u http://target.com -H "Host: FUZZ" -w hosts.txt

# POST data fuzzing
ffuf -u http://target.com -X POST -d "param=FUZZ" -w wordlist.txt
```

### Advanced Options
```bash
# Result filtering
ffuf -u http://target.com/FUZZ -w wordlist.txt -mc 200 -fs 0

# Recursive scanning
ffuf -u http://target.com/FUZZ -w wordlist.txt -recursion -recursion-depth 2

# Proxy settings
ffuf -u http://target.com/FUZZ -w wordlist.txt -x http://proxy:8080

# rate limiting
ffuf -u http://target.com/FUZZ -w wordlist.txt -p 0.1 -t 50
```

### Matching and Filtering
- `-mc`: matchingHTTPstatus codes（such as200,301,302）
- `-ml`: match response line count
- `-mw`: match response word count
- `-ms`: match response size
- `-mr`: match regex
- `-fc/-fl/-fw/-fs/-fr`: reversefiltering

### Output Formats
- `-of json`: JSONFormat
- `-of html`: HTMLFormat
- `-of csv`: CSVFormat
- `-of all`: allFormat

### Practical Points
- Extremely fast fuzzing speed
- Supports simultaneous multi-variable fuzzing
- Powerful result matching and filtering
- Supportsrecursive and rate control

## 5. SQLMap - SQLInjectiondetection andexploitationtools

### Basic Usage
```bash
# Basic SQL injection detection
sqlmap -u "http://target.com/page?id=1"

# Batch target scanning
sqlmap -m targets.txt

# Import from Burp log
sqlmap -l burp.log

# Import from HTTP request file
sqlmap -r request.txt
```

### Advanced Options
```bash
# Database enumeration
sqlmap -u "http://target.com/page?id=1" --dbs

# Table enumeration
sqlmap -u "http://target.com/page?id=1" -D database_name --tables

# Column enumeration
sqlmap -u "http://target.com/page?id=1" -D database_name -T table_name --columns

# Data extraction
sqlmap -u "http://target.com/page?id=1" -D database_name -T table_name -C column1,column2 --dump
```

### Bypasstechniques
```bash
# Tamper scripts
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment,between

# Proxy settings
sqlmap -u "http://target.com/page?id=1" --proxy=http://proxy:8080

# User agent
sqlmap -u "http://target.com/page?id=1" --user-agent="Custom UA"

# Cookie
sqlmap -u "http://target.com/page?id=1" --cookie="session=abc123"
```

### Attack Techniques
- **Boolean-based blind**: Boolean-based blind injection
- **Time-based blind**: Time-based blind injection  
- **Error-based**: Error-based injection
- **UNION query**: UNION query injection
- **Stacked queries**: Stacked queries

### Practical Points
- High automation, supports multiple databases
- Built-in extensive WAF bypass tamper scripts
- Supports various injection techniques and data extraction
- Can generate detailed technical reports

## 6. WPScan - WordPresssecurity scanner

### Basic Usage
```bash
# Basic WordPress scan
wpscan --url http://target.com

# Enumerate plugins
wpscan --url http://target.com --enumerate p

# Enumerate themes
wpscan --url http://target.com --enumerate t

# Enumerate users
wpscan --url http://target.com --enumerate u
```

### Advanced Options
```bash
# Password attack
wpscan --url http://target.com -U admin -P passwords.txt

# customAPItokens
wpscan --url http://target.com --api-token your_token

# Proxy settings
wpscan --url http://target.com --proxy http://proxy:8080

# Stealthy mode
wpscan --url http://target.com --stealthy
```

### Enumeration Options
- `p`: Plugins
- `vp`: Vulnerable plugins
- `ap`: All plugins
- `t`: Themes
- `vt`: Vulnerable themes
- `at`: All themes
- `u`: Users
- `tt`: Timelines

### Attack Modes
- **wp-login**: WordPressloginpageAttacks
- **xmlrpc**: XML-RPCinterfaceAttacks
- **xmlrpc-multicall**: XML-RPCmulti-callAttacks

### Practical Points
- Specialized WordPress security scanning
- Contains latest WordPress vulnerability database
- Supports user enumeration and password brute force
- Configurable API tokens for additional features

## 7. WhatWeb - Webtechnology identification tool

### Basic Usage
```bash
# Basic identification
whatweb target.com

# Detailed output
whatweb -v target.com

# Aggressive scanning
whatweb -a 3 target.com

# Batch scanning
whatweb target1.com target2.com target3.com
```

### Advanced Options
```bash
# Proxy settings
whatweb --proxy http://proxy:8080 target.com

# customHTTPheaders
whatweb --header "User-Agent: Custom" target.com

# Timeout settings
whatweb --timeout 30 target.com

# outputFormat
whatweb --log-brief results.txt target.com
```

### Aggression Levels
- **1**: Default, lightweight scanning
- **2**: Medium, more probing
- **3**: Aggressive, full version detection
- **4**: Most aggressive, including brute force probing

### Identified Content
- Webframeworks（WordPress, Drupal, Joomlaetc.）
- programming languages（PHP, ASP.NET, Javaetc.）
- Webservicestool（Apache, Nginx, IISetc.）
- JavaScriptlibrary（jQuery, React, Angularetc.）
- security devices（WAF, CDNetc.）

### Practical Points
- Fast and accurate technology stack identification
- Supports multiple aggression levels
- Can identify 2000+ web technologies
- Suitable for large-scale reconnaissance

## 8. Nmap - network scanner（Webrelated features）

### Web Scan Scripts
```bash
# HTTP information gathering
nmap -sV --script http-headers,http-methods,http-title target.com

# Web vulnerability scanning
nmap -sV --script http-vuln* target.com

# Web application enumeration
nmap -sV --script http-enum,http-backup-finder target.com

# SSL/TLS analysis
nmap -sV --script ssl-enum-ciphers,ssl-cert target.com
```

### Common Web Scripts
- **http-headers**: HTTPheader information
- **http-methods**: Supports's HTTPmethods
- **http-title**: pagetitle
- **http-enum**: directory and file enumeration
- **http-vuln***: variousWebvulnerability detection
- **ssl-enum-ciphers**: SSLcipher suite enumeration

### Practical Points
- Combines Nmap's network discovery capabilities
- Rich HTTP/NSE script library
- Can be used in combination with other web tools
- Suitable for comprehensive web application assessment

## Tool Combination Strategy

### 1. Web Application Reconnaissance Workflow
```bash
# Step 1: Technology identification
whatweb -a 3 target.com

# Step 2: Directory and file discovery
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -x .php,.html

# Step 3: Subdomain discovery
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Step 4: Detailed vulnerability scanning
nikto -h target.com
```

### 2. Web Vulnerability Exploitation Workflow
```bash
# Step 1: SQL injection detection
sqlmap -u "http://target.com/vuln.php?id=1" --batch

# Step 2: WordPress-specific scanning
wpscan --url http://target.com --enumerate vp,vt,u

# Step 3: Fuzzing parameters
ffuf -u http://target.com/vuln.php?param=FUZZ -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -mc 200,500

# Step 4: Advanced directory brute force
ffuf -u http://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -recursion -recursion-depth 2
```

### 3. Large-Scale Web Scanning Workflow
```bash
# Step 1: Batch target preparation
# Prepare targets.txt file

# Step 2: Parallel technology identification
whatweb -i targets.txt --log-brief whatweb_results.txt

# Step 3: Batch directory brute force
while read target; do
    gobuster dir -u $target -w wordlist.txt -o ${target}_dirs.txt &
done < targets.txt

# Step 4: Priority target deep scanning
sqlmap -m vulnerable_targets.txt --batch --output-dir=sqlmap_results
```

## Best Practices and Considerations

### 1. Legal and Ethics
- Always obtain legal authorization
- Comply with robots.txt and terms of use
- Control scan rates to avoid DoS
- Record all scanning activities

### 2. Technical Best Practices
- Use latest wordlist files (SecLists recommended)
- Combine multiple tools for cross-validation
- Adjust aggression level based on target
- Verify and deduplicate discovered results

### 3. Performance Optimization
- Set thread count and timeout appropriately
- Use appropriate wordlist size
- Process multiple targets in parallel
- Monitor network bandwidth usage

### 4. Evasion Detection
- Use random user agents
- Control request frequency
- Use proxy rotation
- Avoid obvious attack patterns

## Common Issues and Solutions

### 1. Rate Limiting
- Reduce thread count (-t)
- Increase delay (-p in ffuf)
- Use proxy rotation
- Adjust timeout settings

### 2. WAF Bypass
- Use tamper scripts (sqlmap)
- Modify HTTP headers and user agent
- Use HTTPS and legitimate ports
- Disperse scan time and targets

### 3. Authentication Issues
- Provide correct authentication credentials
- Handle CSRF tokens and sessions
- Use Cookie or Token authentication
- Simulate real user behavior

### 4. Result Verification
- Manually verify key findings
- Cross-validate results from different tools
- Check for false positives and false negatives
- Document the verification process