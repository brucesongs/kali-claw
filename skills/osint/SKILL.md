---
name: osint
description: "A specialized skill for intelligence gathering using publicly available sources."
origin: openclaw
version: "0.2.0.2"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
metadata:
  domain: osint
  tool_count: 0
  guide_count: 8
  mitre: "TA0043-Reconnaissance"
  last_reviewed: "2026-09-04"
---




# Skill: Open Source Intelligence (OSINT)

> **Supplementary Files**:
> - `payloads.md` — OSINT attack payloads and command collection (domain reconnaissance, DNS enumeration, subdomain discovery, Google Dorking, email collection, social media intelligence, metadata extraction, Shodan/Censys queries, leaked data queries, technology fingerprinting)
> - `test-cases.md` — Structured test cases (passive reconnaissance, active scanning, OSINT collection, technology fingerprinting) with severity levels and summary tables

## Summary

Osint skill domain covering osint operations.

**Domain**: osint

**MITRE ATT&CK**: TA0043-Reconnaissance

## Description

A specialized skill for intelligence gathering using publicly available sources. OSINT is a core capability in the reconnaissance phase of penetration testing, covering comprehensive information acquisition from domains, emails, and usernames to social media, leaked data, and threat intelligence. This skill focuses on 13 professional OSINT tools and 5 major practical workflows, emphasizing passive collection, compliant operations, and cross-verification.

Difference from the `recon-osint` skill: recon-osint focuses on active reconnaissance (port scanning, directory brute forcing, web fingerprinting), while this skill focuses on passive intelligence gathering (no direct interaction with the target).

## Use Cases

- Pre-engagement passive reconnaissance for penetration testing: Build a complete intelligence profile before touching the target system
- Red team exercise personnel intelligence: Collect target organization employee emails, social accounts, and technology stacks
- Email and credential breach checking: Check if target emails appear in data breaches
- Cross-platform username tracking: Search for specific usernames across 300+ social platforms
- Threat intelligence and attack surface assessment: Discover exposed assets through Shodan, Certificate Transparency, etc.
- Social engineering information preparation: Collect publicly available information about target personnel for phishing exercise preparation

## Core Tools

### Comprehensive Frameworks

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| SpiderFoot | Automated OSINT collection (200+ modules) | `spiderfoot -s target -t ALL -u passive` |
| Recon-ng | Modular web reconnaissance framework | `recon-ng > use recon/domains-hosts/brute_hosts` |
| Maltego | Visual link analysis | GUI: Domain -> DNS Names -> IP Address |
| sn0int | Semi-automated structured OSINT | `sn0int workspace create osint_test` |

### Email and Personnel Intelligence

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| theHarvester | Email, subdomain, and personnel collection | `theHarvester -d example.com -b all` |
| h8mail | Email breach query (20+ data sources) | `h8mail -t target@email.com` |
| Holehe | Email registration detection across 120+ services | `holehe target@email.com` |

### Username and Social Media

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| Sherlock | Username search across 300+ platforms | `sherlock username --json` |

### Network and Device Intelligence

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| Shodan | IoT and server search engine | `shodan host <IP>` |
| PhoneInfoga | Phone number intelligence collection | `phoneinfoga -n +1234567890 -s all` |

### Code and Credentials

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| GitHub Dorking | GitHub sensitive information search | `curl -s "https://api.github.com/search/code?q=..."` |
| Git-Dumper | Offline Git repository download and analysis | `git-dumper https://github.com/user/repo /output` |

## Methodology

### OSINT Five-Phase Process

**Phase 1: Passive Collection**

No direct interaction with the target; use only public data sources.

```bash
# WHOIS domain registration information
whois example.com

# DNS record collection
dig any example.com @8.8.8.8
subfinder -d example.com -o subdomains.txt
dnsx -d example.com -a -silent

# Certificate Transparency query
theHarvester -d example.com -b crtsh

# Search engine passive collection
theHarvester -d example.com -b google

# SpiderFoot fully automated passive scan
spiderfoot -s example.com -t INTERNET_NAME,DNS_ANY,SUBDOMAIN_HTTPS -u passive
```

**Phase 2: Email Intelligence**

Collect target organization emails and check for breaches.

```bash
# Email collection (multiple data sources)
theHarvester -d example.com -b all

# Email format inference
theHarvester -d example.com -b hunter

# Breach checking
h8mail -t user@example.com
h8mail -t @targetdomain.com -l local

# Service registration detection
holehe user@example.com

# PGP key search
gpg --search-keys user@example.com
```

**Phase 3: Username and Social Media**

Track target usernames across major platforms.

```bash
# Cross-platform username search
sherlock username1 username2 --json

# LinkedIn employee search
theHarvester -d "Company Name" -b linkedin

# Twitter association
theHarvester -d example.com -b twitter
```

**Phase 4: Domain and Asset Discovery**

```bash
# Subdomain enumeration (multi-tool cross-verification)
subfinder -d example.com -o subs_subfinder.txt
amass enum -passive -d example.com -o subs_amass.txt

# Merge, deduplicate, and verify
sort -u subs_*.txt | httpx -silent -status-code -title

# DNS brute force
gobuster dns -d example.com -w /usr/share/wordlists/subdomains-top1mil-20000.txt

# Shodan search for exposed devices
shodan search "org:Example Corp"
shodan host <IP>
```

**Phase 5: Credential and Code Leak**

```bash
# GitHub sensitive information search
curl -s "https://api.github.com/search/code?q=org:company+password+in:file"
curl -s "https://api.github.com/search/code?q=user:username+api_key+in:file"
curl -s "https://api.github.com/search/code?q=repo:owner/repo+secret+in:path"

# Breach database query
curl "https://haveibeenpwned.com/api/v3/breachedaccount/<EMAIL>"

# Offline repository analysis
git-dumper https://github.com/user/repo /tmp/repo_analysis
grep -r "password\|api_key\|secret\|token" /tmp/repo_analysis/
```

### Quick Selection Guide

| Scenario | Primary Tool | Alternative |
|----------|-------------|-------------|
| Quick comprehensive scan | SpiderFoot | Recon-ng |
| Email collection | theHarvester + Hunter | h8mail |
| Email breach check | h8mail | HaveIBeenPwned API |
| Email registration detection | Holehe | -- |
| Username tracking | Sherlock | Namechk |
| Phone number intelligence | PhoneInfoga | -- |
| Subdomain enumeration | subfinder + amass | dnsenum, fierce |
| Device search | Shodan | Censys |
| Code leakage | GitHub Dorking | Git-Dumper |
| Visual correlation | Maltego | -- |
| Automation pipeline | Recon-ng | sn0int |

### Defense Perspective

- **OpSec Awareness**: Regularly use Sherlock and h8mail to check your own information exposure
- **Breach Monitoring**: Subscribe to HaveIBeenPwned notifications for timely detection of credential leaks
- **Code Auditing**: Scan organization GitHub repositories for sensitive information (API keys, passwords)
- **Subdomain Governance**: Regularly clean up abandoned DNS records to prevent subdomain takeover
- **Employee Training**: Minimize social media exposure, avoid leaking technology stacks and internal information

## Practical Steps

### Practical Exercise 1: Complete Intelligence Profile of Target Organization

```bash
# Step 1: Domain basic information
whois example.com
dig any example.com @8.8.8.8

# Step 2: Email and personnel collection
theHarvester -d example.com -b all -f recon_report.html

# Step 3: Breach checking
h8mail -t @example.com -o leaks.json

# Step 4: SpiderFoot comprehensive scan
spiderfoot -s example.com -t ALL -u passive -o json > full_osint.json

# Step 5: Visual correlation (Maltego)
# Domain -> DNS Names -> IP -> AS Number -> Organization
```

### Practical Exercise 2: Target Personnel Social Tracking

```bash
# Step 1: Collect employee emails
theHarvester -d example.com -b linkedin

# Step 2: Extract usernames and search across platforms
sherlock user1 user2 user3 --json -o social_accounts.json

# Step 3: Email service association
holehe user@example.com

# Step 4: Phone number intelligence
phoneinfoga -n +1234567890 -s all
```

### Practical Exercise 3: GitHub Code Leak Audit

```bash
# Step 1: Search for organization sensitive files
curl -s "https://api.github.com/search/code?q=org:target+filename:.env" | jq '.items[].html_url'
curl -s "https://api.github.com/search/code?q=org:target+password+in:file" | jq '.items[].html_url'

# Step 2: Search for key credential keywords
for keyword in password secret api_key token private_key aws_access_key; do
  curl -s "https://api.github.com/search/code?q=org:target+${keyword}+in:file" | jq '.items[].html_url'
done

# Step 3: Download suspicious repositories for in-depth analysis
git-dumper https://github.com/target/suspicious-repo /tmp/audit
grep -rn "password\|api_key\|secret\|token\|aws_" /tmp/audit/ --include="*.yml" --include="*.env" --include="*.json"
```

### Practical Exercise 4: Recon-ng Automation Pipeline

```bash
# Launch and create workspace
recon-ng
[recon-ng] > workspaces create target_recon

# Add target domain
[recon-ng] > add domains example.com

# Subdomain enumeration module chain
[recon-ng] > use recon/domains-hosts/brute_hosts
[recon-ng] > run
[recon-ng] > use recon/hosts-hosts/resolve
[recon-ng] > run

# Email collection
[recon-ng] > use recon/domains-contacts/email-harvester
[recon-ng] > set source example.com
[recon-ng] > run

# Export results
[recon-ng] > show hosts
[recon-ng] > show contacts
[recon-ng] > export csv /tmp/recon_results.csv
```

> **For detailed payloads see `payloads.md`, and for the complete test checklist see `test-cases.md`.**

## Online OSINT Resources

### Search Engines and Devices

| Resource | Purpose |
|----------|---------|
| Google advanced operators | `site:`, `inurl:`, `filetype:`, `intitle:` |
| Shodan (shodan.io) | IoT device and server search |
| Censys (censys.io) | Certificate and host data |
| Yandex | Image reverse search (strong recognition capability) |

### Domain and DNS

| Resource | Purpose |
|----------|---------|
| WHOIS (whois.domaintools.com) | Domain registration information |
| crt.sh | Certificate Transparency query |
| DNSdumpster | DNS enumeration |
| VirusTotal | URL/domain analysis |

### Email and Breaches

| Resource | Purpose |
|----------|---------|
| Hunter.io | Email lookup and format inference |
| HaveIBeenPwned | Breach checking |
| DeHashed | Breach database search |
| LeakCheck | Breach checking |

### Threat Intelligence

| Resource | Purpose |
|----------|---------|
| AlienVault OTX | Open-source threat intelligence |
| AbuseIPDB | IP report query |
| GreyNoise | Internet noise filtering |
| IPinfo | IP geolocation and ownership query |

### Business Information (China)

| Resource | Purpose |
|----------|---------|
| Tianyancha | Enterprise information query |
| Qichacha | Enterprise business registration information |
| Aiqicha | Baidu enterprise query |

## Safety Notes

- **Use VPN or Tor**: Avoid exposing your real IP
- **Set request intervals**: Avoid triggering target protection and rate limiting
- **Compliant operations**: Only scan authorized targets, comply with local laws and regulations
- **Encrypted data storage**: Encrypt sensitive intelligence, regularly clean up temporary files
- **Harmless User-Agent**: Use common browser UAs to avoid being identified as a scanner

## Detection Methods

OSINT detection focuses on identifying reconnaissance activity from external sources and monitoring what information about your organization is publicly available. Understanding attacker reconnaissance patterns helps defenders deploy decoys and detect intelligence-gathering activity.

### Network-Level Indicators (Defender Perspective)
- **Certificate Transparency monitoring**: New SSL certificates issued for typosquatted or subdomains of your brand (use `crt.sh` alerts, CertSpotter).
- **DNS enumeration patterns**: Spike in `ANY` queries, `AXFR` attempts, or DNS brute forcing (`subfinder`, `amass`, `gobuster` signature).
- **Shodan / Censys exposure**: Regular export of your org's exposed services from Shodan/Censys; alert on new open ports or services.
- **Search engine dorking**: Google / Bing searches containing `site:yourdomain.com filetype:pdf inurl:admin`; monitor Google Search Console for suspicious query patterns.
- **WHOIS lookups**: Spike in WHOIS queries for your domain from non-trusted resolvers.

### Web Infrastructure Indicators
- **Subdomain takeover monitoring**: Regular `subjack` / `nuclei takeover` scans of own infrastructure; alert on dangling DNS pointing to decommissioned services.
- **Wayback Machine freshness**: Monitor `web.archive.org` for leaked credentials or internal URLs in archived snapshots.
- **GitHub dorking**: Monitor GitHub search for `org:yourcompany password`, `filename:.env org:yourcompany`; use GitGuardian / TruffleHog.
- **Pastebin monitoring**: Use `psbdmp.ws` API or PasteHunter to detect leaked credentials or internal docs.

### Social / Human Recon Indicators
- **LinkedIn scraping patterns**: Spike in profile views from unknown accounts; bulk profile data requests.
- **Twitter / X mention anomalies**: New accounts mentioning your brand keywords; sentiment shift.
- **Job boards**: Monitor your company's job posts for tech stack disclosure (informs attackers about your stack).
- **Employee blog oversharing**: Internal tools / project names disclosed in tech blogs; alert via Google Alerts.

### Decoy / Honeypot Detection
- **Canary tokens**: Embed unique tokens (Thinkst Canary) in documents, DNS records, AWS API keys; alert on token activation.
- **Honeypot subdomains**: Deploy fake `vpn-internal.yourdomain.com`, `git.yourdomain.com` — any DNS resolution indicates enumeration.
- **Fake breach data**: Plant fake user `admin_honeypot` with known password in forums; alert on usage.
- **Honeydocs**: Track unique honeytokens in documents; alert when found in unexpected location.

### SIEM Detection Rules
- **Splunk SPL**: `index=dns query="*.yourdomain.com" | stats count by src_ip | where count > 100`
- **Sigma rule**: `sigma/rules/recon/subdomain_enum.yml` — detects subfinder/amass patterns.
- **AWS CloudTrail**: Alert on `Describe*` API calls from unrecognized ARNs.
- **GitHub**: Audit log monitoring for `repo.*.clone` from new IPs.

## Defense Evasion Techniques

### Stealth Reconnaissance
- **Passive over active**: Prefer `crt.sh` (Certificate Transparency logs) over `nmap -sS`; no packets hit target.
- **Rate limiting**: Cap Shodan / Censys queries to legitimate research patterns; avoid `bulk export` API.
- **Distributed source IPs**: Use residential proxies for active recon; rotate to avoid WAF rate limiting.
- **Off-peak timing**: Schedule active scans during target's off-hours; blend with maintenance traffic.
- **Source port spoofing**: Use `nmap --source-port 53` to look like DNS; `--source-port 80` to look like HTTP.

### Search Engine Dorking Stealth
- **Distributed queries**: Use multiple search engines (Google, Bing, DuckDuckGo, Brave Search) to distribute query load.
- **Search operators in payloads**: Avoid obvious `inurl:admin` patterns; use natural language queries that yield same results.
- **Custom search engines**: Yandex, Baidu, Mojeek often index different content than Google; less likely to be alerted.
- **Search Console manipulation**: Use Google's `site:` operator via custom scripts rather than browser — evades Google's anti-bot.
- **Cached content access**: Use `cache:` operator or `web.archive.org` to view content without hitting target.

### Social Engineering Recon Stealth
- **LinkedIn via proxy**: Use LinkedIn Sales Navigator via legitimate subscription; avoid scraping patterns.
- **Twitter/X API abuse**: Use Twitter API for bulk mention lookups rather than browser scraping.
- **Browser fingerprint variation**: Rotate User-Agent, viewport, language to evade anti-bot (Cloudflare, PerimeterX).
- **Multiple accounts**: Distribute recon across multiple social media accounts to avoid rate limits and pattern detection.
- **Burner accounts**: Use single-use accounts for sensitive recon (no history to correlate).

### Dark Web Monitoring Evasion
- **Tor for dark web research**: Use Tor for pastebin / forum access; rotate circuits per request.
- **VPN chain**: Tor + VPN combination for maximum anonymity during sensitive searches.
- **Forum burners**: Use unique credentials for each dark web forum; assume breach inevitable.
- **Cryptocurrency for paid access**: Use Monero (private) over Bitcoin for forum donations / paid access.

### Code Repository Recon Stealth
- **GitHub API over search**: Use `api.github.com/search/code` with authenticated token rather than `github.com/search` (rate limits, less suspicious).
- **Mirror repositories**: Clone repos to local before searching; avoid `git grep` patterns across many repos.
- **Fork before analyze**: Fork target repo privately before scanning for secrets (don't reveal interest).
- **TruffleHog locally**: Run secret scanners locally rather than uploading to third-party scanning services.

### Email / User Enumeration Stealth
- **SMTP VRFY avoidance**: Avoid `VRFY` command (logged); use `RCPT TO` responses instead.
- **Microsoft 365 enumeration**: Use `GetCredentialType` API endpoint (no log) over `AutoDiscover` (logged).
- **Gmail enumeration**: Use Gmail API rather than SMTP `RCPT TO` (rate-limited but less suspicious).
- **OAuth consentGrant pattern**: Use legitimate OAuth consent flow to enumerate user existence without SMTP.

### Cloud Reconnaissance Stealth
- **AWS S3 enumeration**: Use `ListObjectsV2` with valid credentials (no `Anonymous` flag); less suspicious than anonymous bucket checks.
- **Azure Blob enumeration**: Use Azure Storage Explorer with legitimate SAS tokens over anonymous GET.
- **GCP Bucket enumeration**: Use authenticated API calls rather than anonymous `storage.googleapis.com` GETs.
- **Container registry recon**: Pull images individually with delays rather than bulk `skopeo sync`.

---

## Hacker Laws

- **First Principles Thinking**: The essence of OSINT is information retrieval and correlation. Understanding search engine indexing principles, DNS query mechanisms, and Certificate Transparency protocols is necessary to design efficient collection strategies, rather than blindly stacking tools.
- **Divergent Thinking First**: Verify each intelligence target with at least 3 sources — search engines, certificate logs, DNS brute force, social media crawling. A single source inevitably has blind spots.
- **Trust but Verify**: OSINT data may be outdated, forged, or incomplete. WHOIS may be shielded by privacy protection, breach data may contain false information, social media accounts may be impersonated. All intelligence requires cross-verification.
- **Obscurity Is Not Security**: Information that targets think "nobody will find" is often the most dangerous. Public GitHub repositories, unprotected DNS records, and social media oversharing are all overlooked attack surfaces.

## Learning Resources

- **Supplementary files for this skill**: payloads.md, test-cases.md
- **Related skills**: skills/recon-osint/SKILL.md, skills/social-engineering/SKILL.md, skills/social-intelligence/SKILL.md, skills/deep-research/SKILL.md, skills/password-attack/SKILL.md
- **Tool memory files**: osint/learning/OSINT_TOOLS_GUIDE.md, memory/maltego.md, memory/recon-ng.md
- **External resources**:
  - OSINT Framework: https://osintframework.com
  - TRACE Labs: https://tracelabs.org
  - IntelTechniques: https://inteltechniques.com
- **Core system files**: SOUL.md, TOOLS.md
