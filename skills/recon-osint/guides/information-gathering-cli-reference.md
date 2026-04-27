# Information Gathering Command Line Tools Detailed Reference

## 1. theHarvester - OSINTinformation gathering

### Basic Usage
```bash
# Basic domain information gathering
theHarvester -d example.com -b google,bing

# Use multiple data sources
theHarvester -d example.com -b baidu,duckduckgo,github-code,securityTrails

# Enable DNS resolution and brute force
theHarvester -d example.com -r -c -n

# Save results to file
theHarvester -d example.com -f results.xml

# Enable Shodan queries
theHarvester -d example.com -s
```

### Main Options
- `-d, --domain`: Target domain or company name
- `-b, --source`: Specify data sources (50+ sources supported)
- `-l, --limit`: Limit search results (default 500)
- `-r, --dns-resolve`: DNS resolution for subdomains
- `-c, --dns-brute`: Perform DNS brute force
- `-n, --dns-lookup`: Enable DNS server lookup
- `-s, --shodan`: Use Shodan to query discovered hosts
- `-f, --filename`: Save results to XML/JSON file

### Practical Examples
```bash
# Comprehensive information gathering
theHarvester -d target.com -b all -r -c -n -f target_recon

# Collect emails and hosts only
theHarvester -d target.com -b hunter,haveibeenpwned -l 1000
```

## 2. Sublist3r - subdomain enumeration

### Basic Usage
```bash
# Basic subdomain enumeration
sublist3r -d example.com

# Enable brute force module
sublist3r -d example.com -b

# Specify search engines
sublist3r -d example.com -e google,bing,yahoo

# Scan discovered subdomain ports
sublist3r -d example.com -p 80,443,8080

# Save results
sublist3r -d example.com -o subdomains.txt
```

### Main Options
- `-d, --domain`: Target domain
- `-b, --bruteforce`: Enable subbrute brute force module
- `-p, --ports`: Scan specified TCP ports on discovered subdomains
- `-e, --engines`: Specify search engines (comma-separated)
- `-o, --output`: Save results to text file
- `-t, --threads`: Brute force thread count
- `-v, --verbose`: Enable verbose output

### Practical Examples
```bash
# Quick subdomain discovery
sublist3r -d target.com -e crtsh,securityTrails,virustotal

# Full enumeration with port scanning
sublist3r -d target.com -b -p 21,22,25,80,443,3389 -o full_scan.txt
```

## 3. Amass - Attackssurface mapping

### Basic Usage（Requires API key configuration）
```bash
# Passive enumeration
amass enum -d example.com -passive

# Active enumeration
amass enum -d example.com -active

# Use configuration file
amass enum -d example.com -config ~/.amass-config.ini

# Save results
amass enum -d example.com -o amass_results.txt
```

### Main Options
- `enum`: Enumerate subdomains
- `-d`: Target domain
- `-passive`: Use only passive data sources
- `-active`: Perform active probing
- `-o`: Output file
- `-config`: Configuration file path
- `-brute`: Enable brute force
- `-ip`: Show IP addresses

### Practical Examples
```bash
# Passive information gathering
amass enum -d target.com -passive -o passive_enum.txt

# Active attack surface mapping
amass enum -d target.com -active -brute -ip -o attack_surface.txt
```

## 4. DNSRecon - DNSenumeration and reconnaissance

### Basic Usage
```bash
# Standard enumeration
dnsrecon -d example.com -t std

# Zone transfer test
dnsrecon -d example.com -t axfr

# Brute force subdomains
dnsrecon -d example.com -t brt -D /usr/share/wordlists/dnsmap.txt

# Reverse DNS lookup
dnsrecon -r 192.168.1.0/24 -t rvl

# CRT.sh enumeration
dnsrecon -d example.com -t crt
```

### Main Enumeration Types
- `std`: SOA, NS, A, AAAA, MX, SRV records
- `axfr`: Test zone transfer on all NS servers
- `brt`: Brute force domains and hosts using dictionary
- `rvl`: Reverse lookup for CIDR or IP ranges
- `crt`: Search subdomains via crt.sh
- `zonewalk`: DNSSEC zone walk using NSEC records

### Output Options
- `-x`: Save as XML file
- `-c`: Save as CSV file  
- `-j`: Save as JSON file
- `--db`: Save to SQLite3 database

### Practical Examples
```bash
# Comprehensive DNS reconnaissance
dnsrecon -d target.com -t std,axfr,brt,crt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -j dns_results.json

# Internal IP range reverse lookup
dnsrecon -r 10.0.0.0/24 -t rvl -c internal_hosts.csv
```

## 5. Masscan - ultra-fast port scanner

### Basic Usage
```bash
# Basic port scan
masscan 192.168.1.0/24 -p80,443 --rate=1000

# Scan all ports
masscan 10.0.0.0/8 -p0-65535 --rate=100000

# Enable service identification
masscan 192.168.1.1 -p1-65535 --banners --rate=1000

# Read targets from file
masscan -iL targets.txt -p80,443,8080 --rate=5000
```

### Main Options
- `-p`: Specify ports (supports ranges: 8000-8100)
- `--rate`: Scan rate (packets/second)
- `--banners`: Get service banner information
- `-iL`: Read target list from file
- `-oX`: Save as XML format
- `-oJ`: Save as JSON format
- `--exclude`: Exclude specific IPs
- `--ping`: Enable ICMP ping scan

### Performance Tuning
- Small networks: `--rate=1000`
- Medium networks: `--rate=10000`  
- Large networks: `--rate=100000+`
- Note: Excessively high rates may cause packet loss

### Practical Examples
```bash
# Quick web service discovery
masscan 10.0.0.0/24 -p80,443,8080,8443 --rate=5000 --banners -oJ web_services.json

# Full port scan (use with caution)
masscan 192.168.1.1 -p0-65535 --rate=10000 --banners -oX full_scan.xml
```

## Tool Combination Strategy

### 1. Information Gathering Workflow
```bash
# Step 1: Domain information gathering
theHarvester -d target.com -b all -r -c -n -f phase1

# Step 2: Subdomain enumeration  
sublist3r -d target.com -b -e crtsh,securityTrails -o subdomains.txt

# Step 3: Deep DNS reconnaissance
dnsrecon -d target.com -t std,axfr,brt,crt -D wordlist.txt -j dns_deep.json

# Step 4: IP range discovery and scanning
# Extract IPs from previous results, then use masscan
masscan [IP_LIST] -p1-65535 --rate=10000 --banners -oJ port_scan.json
```

### 2. Passive vs Active Reconnaissance
- **Passive Reconnaissance**: theHarvester (some sources), Amass (passive mode)
- **Active Reconnaissance**: Sublist3r (brute force), DNSRecon (all modes), Masscan

### 3. Data Integration
- All tools support multiple output formats (JSON/XML/CSV)
- Scripts can be written to automatically integrate results from different tools
- Recommended to establish unified data storage and analysis workflow

## Best Practices and Considerations

### 1. Legal and Ethics
- Always obtain authorization before scanning
- Comply with target system's robots.txt and terms of use
- Control scan rates to avoid impacting the target

### 2. Technical Best Practices
- Use latest wordlist files (SecLists recommended)
- Configure API keys to improve data source coverage
- Combine passive and active reconnaissance methods
- Verify and deduplicate discovered results

### 3. Performance Optimization
- Adjust scan rates based on network environment
- Use multi-threading to improve efficiency
- Allocate system resources appropriately
- Monitor network bandwidth usage

### 4. Result Verification
- Manually verify key findings
- Cross-validate results from different tools
- Record scan time and environment information
- Save raw data for subsequent analysis