# 2026-03-21 Information Gathering Command Line Tools Learning

## Mastered Tools

### 1. theHarvester (v4.10.1)
- **Functionality**: OSINT information gathering, supports 50+ data sources
- **Core Commands**: `-d domain -b source -r -c -n -f file`
- **Practical Points**:
  - Primarily passive collection, requires API keys for full functionality
  - Supports DNS resolution, brute force, Shodan integration
  - Rich output formats (XML/JSON)

### 2. Sublist3r
- **Functionality**: Subdomain enumeration tool
- **Core Commands**: `-d domain -b -e engines -p ports -o output`
- **Practical Points**:
  - Combines multiple search engines for better coverage
  - Built-in brute force module (subbrute)
  - Can directly scan discovered subdomain ports

### 3. DNSRecon
- **Functionality**: Comprehensive DNS enumeration and reconnaissance tool
- **Core Commands**: `-d domain -t type -D wordlist -j json_output`
- **Practical Points**:
  - Supports 9 enumeration types (std, axfr, brt, rvl, crt, etc.)
  - Zone transfer testing, reverse DNS, brute force
  - Multi-format output (JSON/XML/CSV/SQLite)

### 4. Masscan
- **Functionality**: Ultra-fast port scanner (10M pps)
- **Core Commands**: `targets -p ports --rate speed --banners -oJ json`
- **Practical Points**:
  - Requires root privileges to run
  - Extremely high scanning speed, suitable for large-scale scans
  - Supports service banner grabbing

### 5. Amass
- **Functionality**: Attack surface mapping and asset discovery
- **Core Commands**: `enum -d domain -passive/-active -config file -o output`
- **Practical Points**:
  - Combines passive and active modes
  - Requires API key configuration for best results
  - Enterprise-grade attack surface management tool

## Tool Combination Strategy

### Information Gathering Workflow
1. **Initial Reconnaissance**: theHarvester + Sublist3r (passive discovery)
2. **Deep DNS**: DNSRecon (active verification and expansion)
3. **IP Discovery**: Extract IPs from domain results
4. **Port Scanning**: Masscan (fast port discovery)
5. **Attack Surface Mapping**: Amass (comprehensive analysis)

### Data Integration
- All tools support JSON output for automated processing
- Build unified data storage and analysis pipeline
- Cross-validate results from different tools to improve accuracy

## Practical Considerations

### Legal Compliance
- Always obtain authorization before scanning
- Comply with target system terms of use
- Control scanning rates to avoid impact

### Technical Optimization
- Use latest SecLists wordlist files
- Configure API keys to improve data source coverage
- Adjust scanning parameters based on network environment
- Verify and deduplicate discovered results

## File Locations
- Detailed command reference: `/home/parallels/.openclaw/workspace/security-tools-67/information-gathering-cli-reference.md`
- This learning record: current file
- Tool classification statistics: `/home/parallels/.openclaw/workspace/kali-517-analysis/`

## Follow-up Learning Plan
- Deep study of web application security tools (Burp Suite CLI, ZAP CLI, etc.)
- Master password attack tools (hashcat, john, etc.)
- Learn post-exploitation tools (crackmapexec, mimikatz, etc.)
