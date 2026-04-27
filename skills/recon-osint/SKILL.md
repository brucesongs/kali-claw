# Skill: Recon & OSINT

> **Supplementary Files**:
> - `payloads.md` — Complete command set categorized by Passive Recon, Active Scanning, Subdomain Enumeration, Technology Fingerprinting, Email Harvesting, Social Media OSINT, Metadata Extraction, and Google Dorks
> - `test-cases.md` — 11 structured test cases covering passive reconnaissance, active scanning, OSINT collection, and technology fingerprinting, with severity levels and verification criteria

## Description

The most critical first step in penetration testing. Information gathering determines the precision and efficiency of subsequent attacks. This skill covers three major areas: passive reconnaissance (OSINT), active reconnaissance (port scanning, service identification), and web fingerprinting — from domain enumeration to directory bruteforcing, building a complete target profile. Mastered tools include nmap, dig, whois, whatweb, wpscan, gobuster, theHarvester, sublist3r, assetfinder, dirb, zenmap, as well as tools currently being learned: maltego, photon, recon-ng, ffuf, dnsenum, fierce, etc.

## Use Cases

- Pre-engagement reconnaissance for penetration testing: comprehensive information gathering on the target, mapping the attack surface
- Red team exercise asset discovery: enumerating subdomains, IP ranges, open services, finding weak entry points
- Security assessment and compliance audits: identifying exposed surfaces, unauthorized services, information leakage
- CTF competition information gathering phase: rapidly locating target services and attack paths
- Threat intelligence tracking: collecting information about the target organization's personnel, emails, and technology stack

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| nmap | Port scanning and service identification | `nmap -sV -sC -O -p- target` |
| dig / whois | DNS enumeration and domain information lookup | `dig any example.com @8.8.8.8` |
| theHarvester | Email, subdomain, and IP collection | `theHarvester -d example.com -b all` |
| sublist3r / assetfinder | Subdomain enumeration | `sublist3r -d example.com -t 50` |
| gobuster / ffuf | Directory and file bruteforcing | `gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt` |
| whatweb / wpscan | Web fingerprinting and CMS identification | `whatweb http://target && wpscan --url http://target` |
| recon-ng | Modular web reconnaissance framework | `recon-ng > use recon/domains-hosts/google_domain_scraper` |
| maltego | Visual OSINT correlation analysis | GUI: Domain -> To DNS Names -> To IP Address |

## Methodology

### Attack Chain

**Step 1: Passive Recon**

No direct interaction with the target, minimizing exposure risk. Collect domain registration information, DNS records, search engine caches, and social media data.

**Step 2: Subdomain and Asset Discovery**

Enumerate all subdomains and associated assets to expand the attack surface. Cross-validate with multiple tools to avoid missing targets.

**Step 3: Active Scanning and Service Identification**

Perform port scanning and service version identification on discovered assets, building a service inventory.

**Step 4: Web Application Fingerprinting and Directory Enumeration**

Identify web technology stacks, CMS, and framework versions; bruteforce hidden directories and files.

**Step 5: OSINT Deep Correlation Analysis**

Cross-correlate collected information and build a complete attack surface map.

### Defense Perspective

- **Restrict DNS Zone Transfers**: Configure DNS servers to reject unauthorized AXFR requests
- **Minimize Information Leakage**: Disable web server version display, remove default pages
- **Monitor Reconnaissance Activity**: Deploy IDS/IPS to detect abnormal scanning patterns, log whois and DNS queries
- **CDN and WAF Deployment**: Hide real IPs, block automated scanning tools
- **Subdomain Takeover Prevention**: Regularly check DNS record pointers, clean up stale CNAME records
- **OSINT Protection Awareness**: Minimize employee social media exposure, avoid leaking technology stack details on public platforms

## Practical Steps

> **Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.**

### Exercise 1: Full Domain Reconnaissance Workflow

1. Basic domain information lookup (whois + dig)
2. Multi-tool subdomain enumeration with cross-validation (sublist3r + assetfinder + dnsenum)
3. Merge, deduplicate, and verify liveness (sort + httpx)

### Exercise 2: Target Network Port Scanning

1. Rapid live host discovery (nmap -sn)
2. Full port deep scan (nmap -sS -sV -sC -O -p-)
3. Visual analysis (zenmap)

### Exercise 3: Web Application Deep Scanning

1. Technology stack identification (whatweb)
2. CMS-specific scanning (wpscan)
3. Dual-tool directory bruteforce verification (dirb + gobuster)

### Exercise 4: Deep Crawling and Correlation Analysis

1. Comprehensive target website crawling (photon)
2. Automated information correlation (recon-ng)
3. Visual correlation analysis (maltego)

## Hacker Laws

- **First Principles Thinking**: Don't blindly rely on tool output. Understand the principles behind DNS queries, TCP handshake mechanisms, and HTTP protocol details. Tools are merely execution mechanisms; principles are the foundation for discovering vulnerabilities.
- **Divergent Thinking First**: Subdomain enumeration is not limited to one approach — search engines, certificate transparency, DNS bruteforcing, crawler extraction, and OSINT correlation. Use at least 3 methods for cross-validation to avoid single-source blind spots.
- **Trust but Verify**: Scan results require verification. Ports reported by nmap may be interfered with by firewalls, whois data may be outdated, and subdomains may be offline. Every finding must be confirmed a second time.
- **Minimize Attack Surface**: From a defensive perspective, every exposed port, DNS record, and directory is a potential entry point. Understanding the attack surface during reconnaissance is essential for effectively narrowing it.

## Learning Resources

### Tool Memory Files (memory/)

- `memory/photon.md` - Photon crawler usage guide and option details
- `memory/dirb.md` - Dirb directory scanner configuration and practical examples
- `memory/dnsenum.md` - Dnsenum DNS enumeration tool usage
- `memory/fierce.md` - Fierce subdomain scanning and DNS analysis
- `memory/maltego.md` - Maltego visual OSINT analysis workflow
- `memory/legion.md` - Legion semi-automated penetration testing framework
- `memory/recon-ng.md` - Recon-ng modular reconnaissance framework guide
- `memory/caido.md` - Caido web proxy tool
- `memory/hping3.md` - Hping3 advanced network probing tool

### Reference Guides (guides/)

- `guides/api_security_complete_guide.md` - API security assessment guide
- `guides/security_misconfiguration_complete_guide.md` - Security misconfiguration identification
- `guides/insecure_design_complete_guide.md` - Insecure design pattern identification

### Core System Files

- `SOUL.md` - Complete hacker laws definition
- `TOOLS.md` - Tool ecosystem overview

**This skill's supplementary files**: payloads.md, test-cases.md
**Related skills**: skills/network-pentest/SKILL.md, skills/social-engineering/SKILL.md
**External resources**:
- [OWASP Information Gathering](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/)
- [SANS OSINT Poster](https://www.sans.org/posters/open-source-intelligence/)
- [Nmap Documentation](https://nmap.org/book/man.html)
