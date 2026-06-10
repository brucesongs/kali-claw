# Tool Selection by Attack Phase Guide

## Introduction

Selecting the right tool for each attack phase is fundamental to efficient penetration testing. This guide provides a systematic approach to tool selection based on engagement phase, target type, and operational constraints. Rather than memorizing hundreds of tools, testers should understand the selection framework that maps requirements to appropriate tools.

Tool selection is not random — it follows a decision tree that considers the target type (web, network, cloud, mobile, API, wireless), the current kill chain phase (recon, scan, enum, vuln, exploit, post-exp), and operational constraints (stealth required, time limited, scope restrictions). Making the right selection the first time saves hours of wasted effort and produces better results.

## Attack Phase Overview

The penetration testing kill chain consists of six primary phases. Each phase has specific goals and requires specialized tools:

1. **Reconnaissance**: Gather information about the target without direct interaction (passive) or with minimal interaction (semi-passive)
2. **Scanning**: Actively probe the target to discover open ports, running services, and potential entry points
3. **Enumeration**: Deep-dive into discovered services to extract detailed information about configurations, users, and data
4. **Vulnerability Discovery**: Identify security weaknesses in enumerated services and applications
5. **Exploitation**: Leverage discovered vulnerabilities to gain unauthorized access or execute code
6. **Post-Exploitation**: Assess the impact of successful exploitation through privilege escalation, lateral movement, and data access

## Phase 1: Reconnaissance Tool Selection

Reconnaissance tools should generate minimal traffic to the target. Prefer passive data sources and cached results over active probing.

### Primary Tools

| Tool | Use Case | Stealth Level |
|------|----------|---------------|
| subfinder | Subdomain enumeration via passive sources | Fully passive |
| amass | Deep subdomain enumeration with active option | Passive or semi-active |
| whatweb | Technology fingerprinting via HTTP headers | Semi-active (one request) |
| theHarvester | Email and subdomain harvesting from public sources | Fully passive |
| httpx | HTTP probing for live host detection | Semi-active |
| waybackurls | Historical URL discovery from Wayback Machine | Fully passive |
| gau | URL aggregation from multiple sources | Fully passive |
| dnsrecon | DNS record enumeration | Semi-active |

### Selection Decision Tree

```bash
# IF target is a domain → start with subfinder + amass
# IF target is an IP range → start with nmap -sn (host discovery)
# IF stealth is critical → use only passive tools (subfinder, waybackurls, gau)
# IF time is limited → use subfinder only (faster than amass)
# IF need email addresses → add theHarvester
# IF need technology stack → add whatweb after httpx probing
```

## Phase 2: Scanning Tool Selection

Scanning tools actively probe the target network. Selection depends on network size, time constraints, and stealth requirements.

### Primary Tools

| Tool | Use Case | Speed | Stealth |
|------|----------|-------|---------|
| nmap | Comprehensive port and service scanning | Moderate | Configurable |
| masscan | Fast port discovery for large networks | Very fast | Low |
| rustscan | Modern fast scanner with nmap integration | Fast | Low |
| nuclei | Template-based vulnerability scanning | Fast | Moderate |
| nikto | Web server misconfiguration detection | Slow | Low |
| testssl | SSL/TLS security assessment | Moderate | Low |

### Selection Decision Tree

```bash
# IF target is a single host → use nmap -sS -sV -sC -p-
# IF target is a large network → use masscan first, then nmap for found ports
# IF stealth required → use nmap -sS -T2 -f with decoys
# IF web target → add nuclei + testssl + nikto
# IF need speed → use rustscan piped to nmap for service detection
# IF need vulnerability baseline → nuclei with cves/ and vulnerabilities/ templates
```

## Phase 3: Enumeration Tool Selection

Enumeration tools extract detailed information from discovered services. Tool selection depends on the service types identified during scanning.

### Primary Tools

| Tool | Use Case | Target Service |
|------|----------|----------------|
| ffuf | Directory and file brute-forcing | Web (HTTP) |
| gobuster | Directory, DNS, and vhost brute-forcing | Web (HTTP/DNS) |
| feroxbuster | Recursive content discovery | Web (HTTP) |
| kiterunner | API endpoint discovery | API |
| arjun | HTTP parameter discovery | Web/API |
| enum4linux | SMB/NetBIOS enumeration | SMB |
| ldapsearch | LDAP directory enumeration | LDAP |
| snmpwalk | SNMP data extraction | SNMP |

### Selection Decision Tree

```bash
# IF HTTP service found → use ffuf for directories, arjun for parameters
# IF API detected → use kiterunner for endpoint discovery
# IF SMB service found → use enum4linux -a
# IF LDAP service found → use ldapsearch
# IF SNMP service found → use snmpwalk with community string
# IF need recursive crawling → use feroxbuster over ffuf
# IF need DNS subdomain enum → use gobuster dns mode
```

## Phase 4: Vulnerability Discovery Tool Selection

Vulnerability discovery tools identify specific security weaknesses. Selection depends on the application type and vulnerability class being tested.

### Primary Tools

| Tool | Use Case | Vulnerability Type |
|------|----------|-------------------|
| sqlmap | SQL injection detection and exploitation | SQLi |
| dalfox | XSS scanning and verification | XSS |
| nuclei | Template-based vulnerability scanning | Multiple |
| commix | Command injection exploitation | Command Injection |
| jwt_tool | JWT token analysis and attacks | Auth Bypass |
| ssrfmap | SSRF detection and exploitation | SSRF |

### Selection Decision Tree

```bash
# IF input fields with database queries → sqlmap
# IF input fields reflected in output → dalfox
# IF known CVE for discovered service → nuclei with specific template
# IF OS command execution suspected → commix
# IF JWT authentication in use → jwt_tool
# IF URL fetching functionality found → test for SSRF
# IF need comprehensive scan → nuclei with all template categories
```

## Phase 5: Exploitation Tool Selection

Exploitation tools leverage vulnerabilities to gain access. This phase requires the most careful authorization and scope verification.

### Primary Tools

| Tool | Use Case | Access Type |
|------|----------|-------------|
| metasploit | Exploitation framework with known exploits | Remote code execution |
| sqlmap | Database access via SQL injection | Data extraction |
| hydra | Online credential brute-forcing | Authentication bypass |
| crackmapexec | Network exploitation with credentials | Lateral movement |
| impacket | Protocol-level exploitation | Various |

### Selection Decision Tree

```bash
# IF known CVE with Metasploit module → msfconsole
# IF SQL injection confirmed → sqlmap --os-shell or --dump
# IF login form discovered → hydra with appropriate module
# IF credentials obtained → crackmapexec for lateral testing
# IF need custom payload → msfvenom for generation
# IF Windows target with credentials → impacket-psexec or evil-winrm
```

## Phase 6: Post-Exploitation Tool Selection

Post-exploitation tools assess the impact of successful access. Focus on privilege escalation, lateral movement, and data extraction.

### Primary Tools

| Tool | Use Case | Platform |
|------|----------|----------|
| linpeas | Linux privilege escalation enumeration | Linux |
| winpeas | Windows privilege escalation enumeration | Windows |
| mimikatz | Credential extraction from memory | Windows |
| chisel | HTTP-based tunneling | Cross-platform |
| ligolo-ng | Tunneling and pivoting | Cross-platform |
| lazagne | Password recovery from local stores | Cross-platform |

### Selection Decision Tree

```bash
# IF Linux target → run linpeas for escalation paths
# IF Windows target → run winpeas + mimikatz for credentials
# IF need network pivot → chisel for HTTP tunnel, ligolo-ng for advanced routing
# IF need credentials from apps → lazagne for browser/app password recovery
# IF need to dump domain hashes → impacket-secretsdump
# IF need to crack obtained hashes → hashcat with appropriate mode
```

## Hands-on Exercise

Practice the tool selection framework:

1. Choose a target type (web, network, cloud, API)
2. Walk through each of the 6 phases and select appropriate tools using the decision tree
3. Document your selections and justify each choice
4. Build a complete tool chain that covers all phases
5. Execute the chain against a lab target and evaluate coverage
6. Identify any gaps where a different tool would have been more effective

## References

- Kali Linux Tools: https://www.kali.org/tools/
- tool-selector.sh source: validation/tool-selector.sh
- PTES Methodology: http://www.pentest-standard.org/
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- HackTricks Methodology: https://book.hacktricks.wiki/
