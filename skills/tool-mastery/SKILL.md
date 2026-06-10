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

Covers tool classification, proficiency levels, verification methods, and combination strategies across the 518-tool Kali arsenal.

**Domain**: knowledge

## Description

Tool Mastery is the foundational knowledge domain covering all 518 Kali Linux security tools organized across 10 primary categories. This skill provides a systematic approach to tool classification, proficiency assessment, verification, and combination strategies. Proficiency is measured on a four-level scale (Beginner, Intermediate, Advanced, Expert) with practical verification commands for each level. The tool classification system maps every tool to one or more attack phases (recon, scan, enum, vuln, exploit, post-exp) enabling intelligent tool selection based on target type, engagement phase, and operational constraints (stealth vs. speed).

## Use Cases

- Assess current tool proficiency across security categories
- Verify tool knowledge before engagement execution
- Discover optimal tool combinations for specific attack scenarios
- Track learning progress for individual tools
- Generate tool selection recommendations by target type

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

1. **Classify** — Map tools to categories (recon, scanning, exploitation, post-exploitation, forensics)
2. **Assess** — Evaluate proficiency level per tool (Beginner, Intermediate, Advanced, Expert)
3. **Verify** — Execute verification commands to confirm practical knowledge
4. **Combine** — Build tool chains for multi-step attack scenarios
5. **Track** — Monitor proficiency growth over time

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

- **Network scanning**: Nmap and masscan produce distinctive SYN flood patterns that IDS/IPS systems detect through signature matching. Defenders use Zeek, Suricata, and Snort rules to flag scan patterns.
- **Web fuzzing**: Directory brute-force tools (ffuf, gobuster) generate high request rates with common paths. WAF rules and rate limiting detect these patterns through 404/error ratios.
- **Password attacks**: Hydra and medusa create high authentication failure rates. Account lockout policies and SIEM alerts detect brute-force attempts.
- **Exploitation frameworks**: Metasploit generates known exploit signatures. EDR products (CrowdStrike, SentinelOne) detect meterpreter payloads and injection techniques.
- **Post-exploitation**: Mimikatz and credential dumping tools are heavily signatured by AV/EDR. Defenders monitor for LSASS access, SAM database reads, and unusual process injection.

Blue teams can use these same tools defensively — running nmap to audit their own exposure, nuclei for continuous vulnerability scanning, and hashcat for password policy enforcement testing.

## Key Decisions

- IF task is stealthy → prefer passive tools (subfinder, amass) over active (nmap -sT)
- IF speed is priority → use aggressive scan profiles (masscan, nuclei -c 50)
- IF target is API → prioritize kiterunner, arjun, postman over traditional web tools
- IF tool fails → check version compatibility, dependencies, and privilege level
- IF multiple tools cover same task → select based on target-specific features (e.g., nuclei for templates, nikto for web server checks)
- IF EDR/AV present → use living-off-the-land techniques over standard exploitation tools

## Quality Criteria

- Tool selections are appropriate for target type and engagement phase
- Command flags are correct, safe, and match operational constraints
- Output interpretation is accurate and validated against a second source
- Tool combinations follow logical attack chain order with proper data handoff
- Proficiency levels are honestly assessed and verified with practical evidence
