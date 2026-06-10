# Tool Proficiency Framework Guide

## Introduction

This guide defines the proficiency assessment framework for Kali Linux security tools. It provides a structured approach to evaluating and improving tool mastery across all 518 tools. Proficiency assessment is not merely theoretical — it requires practical demonstration at each level, with verifiable evidence that the tester can operate the tool effectively in real engagement scenarios.

The framework uses a four-level scale (Beginner, Intermediate, Advanced, Expert) that maps to increasingly complex operational requirements. Each level has specific verification criteria that must be demonstrated through practical exercises, not just theoretical knowledge. This approach ensures that proficiency assessments accurately reflect real-world capability.

## Proficiency Levels

### Level 1: Beginner

Can execute basic commands and interpret simple output. This is the entry point for any tool and represents familiarity with the tool's primary use case.

**Verification criteria**:
- Can launch the tool with default settings and no errors
- Understands the primary use case and when the tool is appropriate
- Can read and interpret basic output (results, status messages, errors)
- Knows how to access help documentation (`-h`, `--help`, `man`)
- Can identify when to use this tool vs. alternatives

**Example verification (nmap)**:
```bash
# Beginner: basic scan
nmap TARGET
nmap -sV TARGET
nmap --help | head -50
```

**Example verification (sqlmap)**:
```bash
# Beginner: basic SQL injection test
sqlmap -u "TARGET/page?id=1" --batch
sqlmap --help | grep -i "tamper\|technique\|level"
```

### Level 2: Intermediate

Understands options, can tune for specific scenarios, and can combine basic options effectively. This level represents day-to-day operational competence.

**Verification criteria**:
- Knows common flags and their effects on tool behavior
- Can adjust scan speed, intensity, and scope for different scenarios
- Understands output formats and can redirect to files for downstream processing
- Can combine basic options effectively for targeted results
- Understands tool limitations and when results may be unreliable

**Example verification (nmap)**:
```bash
# Intermediate: targeted scan with output management
nmap -sS -sV -sC -T4 -p- TARGET -oA results
nmap -sU -p 53,161,123 TARGET -oA udp_results
nmap --script http-enum,http-headers -p 80,443 TARGET -oA web_enum
```

**Example verification (sqlmap)**:
```bash
# Intermediate: targeted injection with tamper scripts
sqlmap -u "TARGET/page?id=1" --batch --dbs --level=3 --risk=2 --tamper=space2comment
sqlmap -r request.txt --batch --technique=BEUSTQ --threads=5
```

### Level 3: Advanced

Can write custom configurations, scripts, and automation. This level enables tool adaptation for unique scenarios that default settings cannot address.

**Verification criteria**:
- Writes custom NSE scripts, Metasploit modules, or Nuclei templates
- Creates custom wordlists and rule sets tailored to specific targets
- Builds automation scripts combining multiple tools into pipelines
- Troubleshoots tool failures, dependency issues, and compatibility problems
- Understands tool internals (how it works, not just how to use it)

**Example verification (nmap)**:
```bash
# Advanced: custom NSE script and evasion
nmap --script custom-vuln-check TARGET
nmap -sS -T2 -f -D RND:10 --data-length 32 --randomize-hosts TARGET
nmap --script "not brute" --script-args="timeout=30" TARGET
```

**Example verification (Metasploit)**:
```bash
# Advanced: custom resource script with conditional logic
cat > auto_exploit.rc <<'EOF'
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_https
set LHOST 0.0.0.0
set LPORT 443
set AutoRunScript post/windows/manage/migrate
set ExitOnSession false
run -j
EOF
msfconsole -r auto_exploit.rc
```

### Level 4: Expert

Can extend tool capabilities, debug source code, and mentor others. This level represents deep understanding that enables contribution to the tool's ecosystem.

**Verification criteria**:
- Contributes to tool development through bug reports, feature requests, or code patches
- Writes comprehensive tool documentation and training materials
- Develops novel techniques using creative tool combinations
- Can debug tool source code when encountering unexpected behavior
- Mentors others and provides expert guidance on edge cases

## Assessment Process

The proficiency assessment follows a structured four-step process that ensures objectivity and repeatability:

1. **Self-assessment**: Rate proficiency for each tool on the 1-4 scale based on honest evaluation of capabilities. Self-assessment provides a baseline but must be verified through practical demonstration.

2. **Practical verification**: Execute tool-specific verification commands that demonstrate the claimed proficiency level. Each level has concrete verification tasks that must produce valid output. Document all verification output as evidence.

3. **Peer review**: Have another qualified tester verify the assessment by reviewing evidence and, where possible, observing tool usage during an engagement. Peer review catches self-assessment bias.

4. **Progress tracking**: Record verified proficiency levels in TOOLS.md with timestamps. Track progress over time to identify skill gaps and learning priorities for future development.

## Category-Specific Requirements

Different tool categories have different minimum proficiency expectations based on how frequently they are used and how critical they are to engagement success:

| Category | Minimum Level (Core Tools) | Verification Method |
|----------|---------------------------|---------------------|
| Scanning | Level 2 | Execute targeted scan with correct flags, interpret service versions |
| Web Exploitation | Level 2 | Identify and exploit common web vulnerabilities independently |
| Network Exploitation | Level 2 | Execute multi-step exploitation chain with credential handling |
| Post-Exploitation | Level 2 | Escalate privileges on target, establish persistence documentation |
| Forensics | Level 1 | Extract and analyze artifacts from disk images and memory dumps |
| Password Attacks | Level 2 | Crack hashes with appropriate rules, select correct hash modes |
| Wireless | Level 1 | Configure adapter, capture handshake, attempt crack |
| Mobile | Level 1 | Connect to device, enumerate app components, decompile APK |
| Crypto/Stego | Level 1 | Identify hash types, attempt crypto operations, detect steganography |

## Hands-on Practice

Apply the proficiency framework through structured exercises:

1. Select 5 tools from different categories and assess your current level
2. For each tool, attempt the verification tasks for the next level above your current assessment
3. Document all verification output as evidence files
4. Identify your weakest category and create a focused learning plan
5. Practice with CTF challenges that require tool usage at your target level
6. Re-assess quarterly to track proficiency growth over time

## References

- Kali Linux Tools Listing: https://www.kali.org/tools/
- Nmap Documentation: https://nmap.org/docs.html
- Metasploit Documentation: https://docs.metasploit.com/
- OWASP Tool Guide: https://owasp.org/www-community/Vulnerability_Scanning_Tools
- IppSec Methodology: https://ippsec.rocks/
- HackTricks: https://book.hacktricks.wiki/
