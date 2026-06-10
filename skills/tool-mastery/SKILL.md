---
name: tool-mastery
description: "Verification and assessment of practical proficiency with Kali Linux security tools. Covers tool classification, proficiency levels, verification methods, and combination strategies across the 518-tool Kali arsenal."
origin: openclaw
version: "0.1.18"
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
  - Agent
metadata:
  domain: knowledge
  tool_count: 0
  guide_count: 2
---




# Tool Mastery

## Summary

Covers tool classification, proficiency levels, verification methods, and combination strategies across the 518-tool Kali arsenal. Provides a structured framework for assessing, tracking, and improving practical competency with every security tool available in Kali Linux, from reconnaissance scanners to post-exploitation frameworks. Enables intelligent tool selection based on target type, engagement phase, and operational constraints.

**Domain**: knowledge

## Description

Tool Mastery is the foundational knowledge domain covering all 518 Kali Linux security tools organized across 10 primary categories. This skill provides a systematic approach to tool classification, proficiency assessment, verification, and combination strategies. Proficiency is measured on a four-level scale (Beginner, Intermediate, Advanced, Expert) with practical verification commands for each level. The tool classification system maps every tool to one or more attack phases (recon, scan, enum, vuln, exploit, post-exp) enabling intelligent tool selection based on target type, engagement phase, and operational constraints (stealth vs. speed).

Tool proficiency directly impacts engagement success. Selecting the wrong tool wastes time and generates unnecessary noise; selecting the right tool with incorrect flags produces unreliable results. This skill ensures practitioners can rapidly identify the most effective tool for any given task, execute it with appropriate options, interpret its output accurately, and chain its results into the next phase of testing. The skill also addresses tool failure scenarios — when a primary tool is blocked, deprecated, or produces unexpected output, practitioners must know alternative tools and fallback approaches within the same category.

The 518 tools span a wide technology surface: web application testing (SQL injection, XSS, SSRF, authentication bypass), network exploitation (SMB, Active Directory, Kerberos, SNMP), wireless attacks (WiFi, Bluetooth, SDR), mobile security (Android, iOS), cloud and container security, digital forensics and incident response, reverse engineering and binary analysis, cryptographic attacks, and social engineering. Each category has primary tools for common tasks and specialized tools for edge cases.

## Use Cases

- Assess current tool proficiency across security categories and identify skill gaps before engagements
- Verify tool knowledge before engagement execution with practical command validation
- Discover optimal tool combinations for specific attack scenarios (e.g., recon-to-exploit chains)
- Track learning progress for individual tools over time using proficiency level milestones
- Generate tool selection recommendations by target type (web, network, cloud, mobile, API, wireless)
- Troubleshoot tool failures by identifying alternative tools within the same category
- Build custom tool chains for multi-phase attack scenarios with proper data handoff
- Evaluate new Kali tools for inclusion in engagement workflows and update TOOLS.md accordingly
- Plan training schedules by mapping low-proficiency tools to upcoming engagement requirements

## Core Tools

| Tool | Category | Purpose | Key Command |
|------|----------|---------|-------------|
| nmap | Scanning | Network discovery and port scanning | `nmap -sC -sV -oA scan target` |
| sqlmap | Web Exploitation | Automated SQL injection detection and exploitation | `sqlmap -u "url" --dbs` |
| metasploit | Exploitation | Exploit development and payload delivery framework | `msfconsole` |
| burpsuite | Web Exploitation | Web application security testing platform | `burpsuite` |
| nuclei | Scanning | Template-based vulnerability scanner | `nuclei -u target -t cves/` |
| hydra | Password Attacks | Online password brute-forcing tool | `hydra -l user -P pass.txt target ssh` |
| hashcat | Password Attacks | GPU-accelerated password hash cracking | `hashcat -m 0 hash.txt wordlist` |
| subfinder | Reconnaissance | Subdomain discovery via passive sources | `subfinder -d target.com` |
| masscan | Scanning | Mass IP port scanner for large networks | `masscan -p1-65535 target --rate=1000` |
| crackmapexec | Network Exploitation | Network situational awareness and exploitation | `crackmapexec smb target -u user -p pass` |
| aircrack-ng | Wireless | WiFi security assessment suite | `aircrack-ng capture.cap -w wordlist` |
| frida | Mobile | Dynamic instrumentation toolkit for mobile apps | `frida -U -f com.app -l script.js` |
| volatility | Forensics | Memory forensics framework | `vol.py -f memory.dmp windows.pslist` |
| binwalk | Forensics | Firmware analysis and extraction tool | `binwalk -Me firmware.bin` |
| impacket | Network Exploitation | Python class library for network protocols | `impacket-psexec domain/user:pass@target` |
| ffuf | Web Exploitation | Fast web fuzzer for directories and parameters | `ffuf -u url/FUZZ -w wordlist.txt` |
| linpeas | Post-Exploitation | Linux privilege escalation enumeration script | `./linpeas.sh` |
| chisel | Post-Exploitation | HTTP/SOCKS tunnel for pivoting and relay | `chisel server -p 8080 --reverse` |

## Methodology

1. **Classify** — Map tools to categories (recon, scanning, exploitation, post-exploitation, forensics) and attack phases to enable rapid lookup
2. **Assess** — Evaluate proficiency level per tool (Beginner, Intermediate, Advanced, Expert) using the four-level framework with concrete criteria
3. **Verify** — Execute verification commands to confirm practical knowledge at each proficiency level; run tool against known targets with expected outcomes
4. **Combine** — Build tool chains for multi-step attack scenarios; ensure output formats are compatible between chained tools (e.g., nmap XML → searchsploit, subfinder output → httpx probing)
5. **Track** — Monitor proficiency growth over time; record each tool usage session in TOOLS.md with flags, results, and lessons learned
6. **Adapt** — When tools fail or are blocked, immediately switch to the next-best alternative within the same category; document which alternatives work under specific conditions

## Tool Categories

| Category | Tool Count | Key Tools |
|----------|-----------|-----------|
| Reconnaissance | 45 | subfinder, amass, whatweb, theHarvester |
| Scanning | 38 | nmap, masscan, nuclei, rustscan |
| Web Exploitation | 52 | sqlmap, burpsuite, dalfox, ffuf |
| Network Exploitation | 35 | metasploit, crackmapexec, impacket |
| Password Attacks | 18 | hydra, hashcat, john, medusa |
| Post-Exploitation | 28 | mimikatz, chisel, ligolo, linpeas |
| Forensics | 32 | volatility, autopsy, binwalk, strings |
| Wireless | 15 | aircrack-ng, wifite, reaver |
| Crypto | 12 | openssl, hashid, rsatool |
| Mobile | 22 | frida, objection, drozer, jadx |

## Proficiency Levels

| Level | Description | Verification |
|-------|-------------|--------------|
| Beginner | Can run basic commands | Execute help command and describe primary use |
| Intermediate | Understands options and output | Execute targeted scan/exploit with correct flags |
| Advanced | Custom configurations and scripting | Write custom scripts/modules for the tool |
| Expert | Can extend and troubleshoot | Debug tool failures, contribute improvements |

## Practical Steps

1. **Identify target type** — Determine if the target is web, network, cloud, mobile, API, wireless, or a combination
2. **Select tool category** — Map target type to relevant tool categories (recon, scanning, web, network, exploitation, etc.)
3. **Choose specific tools** — Use tool-selector.sh or the category table to pick primary and alternative tools
4. **Determine operational mode** — Select stealth or aggressive flags based on engagement constraints
5. **Execute verification** — Run tools with appropriate flags, capture output in structured evidence files
6. **Chain tool outputs** — Pipe or redirect one tool's output as input to the next tool in the attack chain
7. **Verify results** — Cross-validate findings with a second tool from the same category to reduce false positives
8. **Document proficiency** — Record tool usage, flags, and results for proficiency tracking in TOOLS.md

## Defense Perspective

Understanding security tools from the defender's viewpoint is critical for both offensive and defensive practitioners. Every tool leaves artifacts that detection systems can identify:

- **Network scanning**: Nmap and masscan produce distinctive SYN flood patterns that IDS/IPS systems detect through signature matching. Defenders use Zeek, Suricata, and Snort rules to flag scan patterns. Network flow analysis tools (Argus, SiLK) can detect scan patterns even when individual packets appear normal.
- **Web fuzzing**: Directory brute-force tools (ffuf, gobuster) generate high request rates with common paths. WAF rules and rate limiting detect these patterns through 404/error ratios. Log correlation engines flag the characteristic sequential path enumeration pattern.
- **Password attacks**: Hydra and medusa create high authentication failure rates. Account lockout policies and SIEM alerts detect brute-force attempts. Smart password attack tools that throttle requests can still be detected through temporal analysis of login failures across multiple accounts (password spraying detection).
- **Exploitation frameworks**: Metasploit generates known exploit signatures. EDR products (CrowdStrike, SentinelOne) detect meterpreter payloads and injection techniques. Framework-generated payloads contain distinctive patterns in their PE headers, section names, and entropy distributions.
- **Post-exploitation**: Mimikatz and credential dumping tools are heavily signatured by AV/EDR. Defenders monitor for LSASS access, SAM database reads, and unusual process injection. Credential access events in Windows Event Log (Event ID 4656, 4663) provide forensic evidence.
- **Reconnaissance tools**: Passive recon tools (subfinder, amass, theHarvester) leave footprints in DNS query logs, certificate transparency logs, and API access patterns. While harder to detect, defenders can monitor for unusual query volumes from security research platforms.
- **Forensic tools**: Volatility, binwalk, and autopsy leave no network footprint but create artifacts on the analysis system. Defenders should ensure forensic workstations are isolated and that evidence handling follows chain-of-custody procedures.

Blue teams can use these same tools defensively — running nmap to audit their own exposure, nuclei for continuous vulnerability scanning, hashcat for password policy enforcement testing, and ffuf to discover forgotten endpoints before attackers do. Purple team exercises that run offensive tools against production monitoring help calibrate detection rules and identify blind spots.

## Key Decisions

- IF task is stealthy → prefer passive tools (subfinder, amass) over active (nmap -sT)
- IF speed is priority → use aggressive scan profiles (masscan, nuclei -c 50)
- IF target is API → prioritize kiterunner, arjun, postman over traditional web tools
- IF tool fails → check version compatibility, dependencies, and privilege level
- IF multiple tools cover same task → select based on target-specific features (e.g., nuclei for templates, nikto for web server checks)
- IF EDR/AV present → use living-off-the-land techniques over standard exploitation tools

## Tool Selection Matrix

| Target Type | Primary Tools | Secondary Tools | Phase Focus |
|-------------|---------------|-----------------|-------------|
| Web Application | sqlmap, burpsuite, ffuf, nuclei | dalfox, nikto, whatweb | recon → vuln → exploit |
| Internal Network | nmap, crackmapexec, impacket | responder, bloodhound, enum4linux | scan → enum → exploit |
| Cloud Infrastructure | scoutsuite, pacu, cloudsploit | s3scanner, cloudenum | enum → vuln → exploit |
| Mobile App | frida, objection, jadx | drozer, mobsf, apkleaks | reverse → vuln → exploit |
| API | kiterunner, arjun, postman | httpie, restler, burpsuite | enum → vuln → fuzz |
| Wireless | aircrack-ng, wifite, reaver | bettercap, bully, hostapd-wpe | recon → attack → capture |
| Active Directory | bloodhound, impacket, crackmapexec | ldapsearch, kerbrute, rubeus | enum → exploit → pivot |

## Learning Path

Progress through tool mastery in phases aligned with engagement complexity:

1. **Foundation (Tools 1-50)** — Master the top 50 tools: nmap, sqlmap, burpsuite, metasploit, hydra, hashcat, nuclei, subfinder, ffuf, crackmapexec. These cover 80% of engagement scenarios.
2. **Expansion (Tools 51-150)** — Add specialized tools per domain: wireless (aircrack-ng, reaver), mobile (frida, jadx), cloud (scoutsuite, pacu), forensics (volatility, autopsy).
3. **Specialization (Tools 151-300)** — Deep-dive into niche tools for specific attack vectors: SCADA/ICS, firmware, VoIP, Bluetooth, SDR, anti-forensics.
4. **Comprehensive (Tools 301-518)** — Cover the full arsenal including auxiliary tools, utilities, and rarely-used but scenario-critical tools.

## Tool Failure Recovery

| Failure Type | Diagnosis | Recovery Action |
|--------------|-----------|-----------------|
| Tool crash/segfault | Check dmesg, ldd for missing libs | Reinstall package, use static binary |
| Permission denied | Verify user context, capabilities | Use sudo, set capabilties, or switch tool |
| No results/false negatives | Compare with secondary tool | Use alternative tool, adjust scan parameters |
| Blocked by WAF/IDS | Verify traffic reaches target | Switch to evasive flags, use proxy, change tool |
| Output format incompatible | Check output format flags | Use format converters, custom parsing scripts |
| Rate limited | Check response headers | Add delays, use distributed scanning, rotate proxies |

## Common Pitfalls

- Running tools with default settings against hardened targets — always customize flags based on recon data
- Ignoring tool version compatibility — older nmap scripts may not work with newer NSE libraries
- Relying on a single tool for critical findings — always cross-validate with a second independent tool
- Skipping output verification — tool output can contain false positives or misinterpretations
- Over-looking tool update frequency — outdated tools miss newly-discovered vulnerabilities
- Not reading tool documentation thoroughly — many tools have hidden options that significantly improve results

## Tool Output Formats

| Tool | Default Output | Parseable Format | Integration |
|------|---------------|------------------|-------------|
| nmap | terminal | XML (`-oX`), grepable (`-oG`) | searchsploit, metasploit db_import |
| sqlmap | terminal | CSV (`--csv`), JSON (API mode) | custom parsers |
| nuclei | terminal | JSON (`-json`), SARIF (`-sarif`) | GitHub Security tab, DefectDojo |
| masscan | terminal | list (`-oL`), XML (`-oX`) | nmap feeder |
| subfinder | terminal | JSON (`-json`) | httpx, dnsx |
| hashcat | terminal | potfile, JSON (`--status-json`) | custom dashboards |

## Quality Criteria

- Tool selections are appropriate for target type and engagement phase
- Command flags are correct, safe, and match operational constraints
- Output interpretation is accurate and validated against a second source
- Tool combinations follow logical attack chain order with proper data handoff
- Proficiency levels are honestly assessed and verified with practical evidence
