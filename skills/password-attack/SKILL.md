---
name: password-attack
description: "Password attacks encompass the complete attack chain from hash extraction, hash type identification, dictionary attacks, rule-based attacks, and bruteforcing to online service brute forcing."
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
metadata:
  domain: credential-access
  tool_count: 6
  guide_count: 7
  mitre: "TA0006-Credential Access"
---




# Skill: Password Attacks

> **Supplementary Files**:
> - `payloads.md` — Complete attack payloads organized into eight categories: Online Attacks, Offline Hash Cracking, Wordlist Generation, Hash Identification, Password Spray, Credential Stuffing, NTLM/NetNTLM, and Password Policy Analysis
> - `test-cases.md` — 12 structured test cases covering Online Attacks, Offline Cracking, Wordlist & Mutation, and Advanced Techniques, with severity levels and statistics

## Summary

Password Attack skill domain covering credential access operations.

**Tools**: hashcat, john, hydra, medusa, cewl, crunch

**Domain**: credential-access

**MITRE ATT&CK**: TA0006-Credential Access

## Description

Password attacks encompass the complete attack chain from hash extraction, hash type identification, dictionary attacks, rule-based attacks, and bruteforcing to online service brute forcing. Core attack techniques include dictionary attack, rule-based attack, rainbow table, mask attack, as well as two fundamentally different attack paradigms: online brute force vs offline hash cracking.

Offline attacks target already-obtained hashes (e.g., NTLM, SHA, bcrypt), where attack speed is limited only by hardware and does not trigger target system alerts. Online attacks target remote services (SSH, HTTP, databases) and must contend with defenses such as rate limiting and account lockout.

**Key Insight**: The essence of password attacks is a game of probability and time — dictionary quality determines hit rate, rule engines expand coverage, hardware compute power determines speed, and defense strategies determine the feasibility of online attacks.

---

## Use Cases

1. **Post-Exploitation Credential Extraction** - Extract hashes from SAM database, /etc/shadow, Kerberos TGT, etc., and crack them offline for lateral movement
2. **Web Application Authentication Testing** - Perform online dictionary/brute force attacks against login forms and API endpoints to assess password policy strength
3. **File Password Recovery** - Crack password protection on ZIP, PDF, Office documents, KeePass databases, 1Password, and other encrypted files
4. **CTF Password Cracking** - Rapidly identify hash types and select optimal attack modes and dictionaries to complete challenges
5. **Red Team Custom Dictionary Construction** - Generate customized dictionaries based on target organization information (website content, employee names, corporate culture)

---

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **hashcat** | GPU-accelerated offline hash cracking, 300+ hash types | `hashcat -a 0 -m 1000 hashes.txt wordlist.txt` |
| **john** | Automatic hash detection, excels at single cracking and file passwords | `john --wordlist=rockyou.txt hashes.txt` |
| **hydra** | Online brute forcing across 50+ protocols (SSH/FTP/HTTP/databases) | `hydra -l admin -P pass.txt ssh://target` |
| **medusa** | Parallel modular online brute forcing with flexible parameter configuration | `medusa -h target -u admin -P pass.txt -M ssh` |
| **cewl** | Crawl target website to generate customized password dictionaries | `cewl https://target.com -d 2 -m 4 -w dict.txt` |
| **crunch** | Generate password combination dictionaries by character set and pattern | `crunch 6 8 -t company@%%% -o dict.txt` |

---

## Methodology

### Attack Chain

```
Hash Extraction     Hash Identification   Dictionary/Rule      Offline Cracking
(secretsdump,      (hash-iid,           Selection            (hashcat/john,
 /etc/shadow)       hashcat -I)          (rockyou/cewl/        rules/masks)
                                         crunch/mangling)         |                   |                  |                  |
       v               v                  v                  v
Credential          Online Brute        Credential          Lateral Movement
Verification        Force               Stuffing/Spray      (impacket/wmiexec)
(verify cracked     (hydra/medusa)
 results)
```

**Phase Details**:

1. **Hash Extraction** - Obtain password hashes from target systems: Windows (SAM/NTDS.dit), Linux (/etc/shadow), databases (MySQL/PostgreSQL hash), application configuration files
2. **Hash Identification** - Determine the hash algorithm type and select the correct hashcat mode or john format, which directly affects cracking success rate
3. **Dictionary/Rule Selection** - Select base dictionaries based on target characteristics, combined with rule engines (best64/dive/T0XlC) and mask attacks to expand coverage
4. **Offline Cracking** - Dictionary attack -> Rule attack -> Combination attack -> Mask bruteforce, executed in order of increasing cost-effectiveness
5. **Online Brute Force** - Authentication testing against remote services, controlling concurrency and speed to avoid triggering defenses
6. **Credential Stuffing / Password Spraying** - Try cracked credentials against other services, or test many accounts with a few common passwords
7. **Lateral Movement** - Use obtained credentials to expand access within the target network

### Defense Perspective

| Defense Measure | Description | Attack Type Countered |
|-----------------|-------------|----------------------|
| Strong Hash Algorithms (bcrypt/argon2) | Slow hashes increase offline cracking time cost | Offline hash cracking |
| Salt | Eliminates rainbow table attacks; same passwords produce different hashes | Rainbow table attacks |
| Password Complexity Policy | Enforce length and character set diversity requirements | Dictionary/brute force attacks |
| Rate Limiting | Limit authentication attempts per unit time | Online brute forcing |
| Account Lockout | Lock accounts after consecutive failures | Targeted online brute forcing |
| MFA/2FA | Add a second authentication factor | Post-credential-leakage abuse |
| Password Breach Detection | Compare against Have I Been Pwned and similar databases | Known password reuse |

---

## Practical Steps

> **Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.**

### Core Workflow Overview

1. **Hashcat Offline Cracking** - Identify hash type (`--identify`), then progressively attack in order: dictionary -> rules -> combination -> mask
2. **John the Ripper Flexible Cracking** - Use `--single` mode to generate candidate passwords from username/GECOS information; use `2john` tools to extract file hashes
3. **Hydra Online Brute Force** - Supports 50+ protocols; control concurrency (`-t`) and interval (`-W`) to avoid triggering defenses
4. **Custom Dictionaries** - Three-layer dictionary construction strategy: cewl website keyword crawling + crunch pattern generation + rule mutation
5. **Hash Type Identification** - Quickly determine algorithm type through prefix features (`$2b$`, `$6$`, `$kerberoast$`) and length

---

## Hacker Laws

1. **Murphy's Security Law** - If a weak password could exist, it definitely does. Users will always choose the most convenient password; defenders must assume the worst and enforce password policies.

2. **The Weakest Link Is Human** - Technically perfect password policies will be undermined by users writing passwords on sticky notes, sending them via email, or reusing them across sites. Password attack success often depends on human behavioral patterns rather than algorithm weaknesses.

3. **Trust but Verify** - Cracked credentials must be verified as valid. Passwords may have expired, accounts may be disabled, or hashes may have been updated. Do not assume cracking success equals access success.

4. **Assume Breach** - Design authentication systems assuming attackers have already obtained the hash database. This requires using slow hashes (bcrypt/argon2), global salts, and multi-factor authentication (MFA) to increase cracking costs.

---

## Integration with Other Skills

- **web-auth-bypass**: Use cracked credentials to test authentication bypass scenarios
- **post-exploitation**: Credential harvesting feeds back into password attack wordlists
- **recon-osint**: OSINT-gathered personal info improves targeted wordlist generation
- **crypto-attacks**: Weak cryptographic implementations may expose password hashes

## Common Pitfalls

- Running online attacks without checking lockout policies first
- Using generic wordlists when target-specific mutations would be more effective
- Ignoring password reuse across services (credential stuffing opportunity)
- Not verifying cracked credentials before reporting

## Reporting and Documentation

Password attack findings should document the hash type, cracking method, time invested, and the dictionary or rules used for each successful crack. Report the effective cracking rate (hashes per second) alongside the hardware used, as this contextualizes the strength of the password policy. Include specific recommendations: switch from MD5/SHA to bcrypt/argon2id, increase minimum password length, implement MFA, and deploy breach-password screening (Have I Been Pwned integration). Never include plaintext cracked passwords in reports — reference them by hash and username only.

## Legal and Ethical Considerations

Online brute force attacks against production systems carry significant legal risk and can cause account lockouts for legitimate users. Always verify that online attacks are within the authorized scope and use low concurrency rates to avoid disruption. Offline hash cracking on extracted credential databases is generally less risky but ensure the hash extraction itself was authorized. Never use cracked credentials to access systems outside the defined scope, and destroy all credential databases after the engagement report is delivered unless retention is explicitly required.

## Case Studies and Examples

- **NTLM hash chain attack**: During a post-exploitation assessment, secretsdump extracted 2,400 NTLM hashes from a domain controller. Hashcat with the dive rule set cracked 38% within 4 hours using a consumer GPU, including a domain admin account with the password "Company2025!" — a pattern matching the organization's password policy but vulnerable to rule-based mutation attacks.
- **Targeted dictionary success**: A custom dictionary built from the target company's website (cewl) combined with common mutation rules (capitalize, append year, append special character) cracked a supposedly strong password "M@nufacturing2024" in under 2 minutes that would have taken days with generic wordlists.
- **Credential stuffing across services**: A cracked email password from a web application was reused successfully against the company's VPN, Office 365, and internal wiki — demonstrating the compounding risk of password reuse across an organization's service portfolio.

## Detection Methods

Defenders detect password attacks through several indicators: spikes in authentication failure rates (Event ID 4625 on Windows), unusual patterns in hash extraction attempts (LSASS memory access by unauthorized processes), high GPU utilization on employee workstations indicating local cracking, and credential stuffing detected by login correlation across multiple accounts from the same source IP. Organizations should implement canary accounts with monitored passwords to detect credential stuffing campaigns early.

## Defense Evasion Techniques

Evade detection during authorized password testing by: throttling online brute force attempts to match normal authentication patterns rather than aggressive parallelism, distributing requests across multiple source IPs or through a proxy chain, using password spraying (one password against many accounts) rather than targeted brute force to reduce per-account failure counts, and scheduling attacks during business hours when authentication noise is naturally higher. For offline cracking, perform hash cracking on isolated GPU rigs that are not monitored by endpoint detection tools.

## Advanced Techniques

Advanced password attack techniques include: combinator attacks that join words from two separate dictionaries (effective against passphrase policies), prince attacks that generate candidate passwords by combining random dictionary substrings, keyboard-walk pattern generation for passwords like "qwerty123", mask attacks informed by the target's password policy structure (e.g., `?u?l?l?l?l?d?d?d?s` for "Capital + 4 lowercase + 3 digits + special"), and using machine learning models trained on leaked password databases to generate statistically likely candidates that bypass traditional dictionaries.

## Tool Comparison Matrix

| Tool | Best For | Speed | Coverage | Skill Level |
|------|----------|-------|----------|-------------|
| **hashcat** | GPU offline cracking | Very fast | 300+ hash types | Intermediate |
| **john** | Auto-detection, file passwords | Fast | Broad | Beginner |
| **hydra** | Online brute force (50+ protocols) | Network-bound | 50+ protocols | Beginner |
| **medusa** | Parallel online brute force | Network-bound | Moderate | Intermediate |
| **cewl** | Custom wordlist generation | Slow (web crawling) | N/A | Beginner |
| **crunch** | Pattern-based wordlist generation | Fast (local) | N/A | Beginner |

## Performance and Remediation

GPU cracking performance varies by hash algorithm: MD5/SHA1 achieve billions of hashes per second on modern GPUs, while bcrypt drops to thousands and argon2id to hundreds per second. For fast hashes, use large dictionaries with comprehensive rules; for slow hashes, prioritize targeted dictionaries built from OSINT data. Remediation should enforce bcrypt/argon2id with high iteration counts, implement minimum 12-character passwords, deploy MFA on all critical services, and integrate breach-password screening (Have I Been Pwned) to prevent users from choosing previously compromised passwords.

---

## Learning Resources

- **This skill's supplementary files**: `payloads.md`, `test-cases.md`
- **Related skills**: `skills/web-auth-bypass/SKILL.md`, `skills/crypto-attacks/SKILL.md`
- **Workspace internal resources**: `memory/2026-03-21-password-attack-tools.md` - Complete tool learning notes, including tool combination strategies and practical considerations
- **Hashcat Official Documentation**: [hashcat.net/wiki](https://hashcat.net/wiki/) - Complete reference for attack modes, hash types, and rule syntax
- **John the Ripper Official Wiki**: [openwall.com/john](https://www.openwall.com/john/) - Format support, configuration options, and best practices
- **Hydra GitHub**: [github.com/vanhauser-thc/thc-hydra](https://github.com/vanhauser-thc/thc-hydra) - Protocol modules and usage instructions
- **SecLists**: [github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists) - Comprehensive security dictionaries and payload collections
- **HackTricks - Password Cracking**: [book.hacktricks.xyz](https://book.hacktricks.xyz/generic-methodologies-and-resources/brute-force)
