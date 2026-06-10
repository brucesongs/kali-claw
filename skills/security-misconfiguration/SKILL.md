---
name: security-misconfiguration
description: "Security misconfiguration detection (OWASP A02:2025) covering default credentials, unnecessary services, verbose errors, missing security headers, and directory listing exposures across deployed systems."
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
  domain: defense
  tool_count: 5
  guide_count: 8
  owasp: "A02:2025-Misconfiguration"
---




# Skill: security configurationerrorDetect / Security Misconfiguration Detection

> **Supplementary Files**:
> - `payloads.md` — byclassotherorganization attackpayloadandtestingcommand（HTTP Header、TLS/SSL、defaultcredentials、directorylist、CORS、Cookie etc.）
> - `test-cases.md` — structureizetestinguseexample，with severelevelotherandverifyStep（HTTP Security、TLS/SSL、Default Config、Information Disclosure、CORS/Cookie）

## Summary

Security Misconfiguration skill domain covering defense operations.

**Tools**: Nmap, Nikto, testssl.sh, Burp Suite, WhatWeb

**Domain**: defense

**OWASP**: A02:2025-Misconfiguration

## Description

Security misconfiguration detection (OWASP A02:2025) covering default credentials, unnecessary services, verbose errors, missing security headers, and directory listing exposures across deployed systems. Misconfigurations are the most common and easily overlooked vulnerability class — not a tool flaw but a deployment and maintenance failure that degrades overall security posture.

**coreDetect领domain**:
- **Default Credentials**: output厂defaultusernamepasswordnot modify（admin/admin、root/root、test/test）
- **Unnecessary Services**: productionenvironmentlegacydebugport、managementinterface、exampleapplication
- **Verbose Errors**: stacktrackingleakagefilepath、databasetype、frameworkversion、SQL statement
- **Missing Security Headers**: missing X-Frame-Options、CSP、HSTS、X-Content-Type-Options etc.criticalprotectionhead
- **Directory Listing**: Web serverallowslistdirectorycontent，exposurebackupfile、configurationfile、databasedump

---

## Use Cases / Use Cases

1. **Web applicationpenetration testing** - fortargetperformcomprehensive configurationsecurity audit，discoveryexposure managementinterface、defaultinstallpage、sensitivefile
2. **basic facilitysecurity assessment** - Detectserveronrun 冗余service、openport、defaultconfiguration
3. **TLS/SSL security audit** - assessmentcertificateconfiguration、protocolversion、passwordsetpiecestrongdegree
4. **cloudresourceconfigurationreview** - check S3 Bucket publicaccess、IAM policyoveratlenient、security grouprulenotwhen
5. **complianceitycheck** - for照 CIS Benchmark、OWASP ASVS etc.standardverifyconfigurationcompliance

---

## Core Tools / Core Tools

| Tool | Purpose | Command Example |
|------|------|----------|
| **Nmap** | serviceEnumerate、versionDetect、scriptScan | `nmap -sV -sC --script=default,vuln target` |
| **Nikto** | Web serverconfigurationvulnerability scanning | `nikto -h http://target -o report.html -Format htm` |
| **testssl.sh** | TLS/SSL configurationcomprehensive Detect | `testssl.sh --full --quiet target:443` |
| **Burp Suite** | HTTP Header analysis、responsecheck、Scanner module | Proxy intercept -> check Response Headers -> Scanner maindynamicScan |
| **WhatWeb** | Web techniquefingerprinting、frameworkversionDetect | `whatweb -v http://target` |

auxiliaryTool: **curl**（manual Header check）、**Gobuster**（directory/file暴powerdiscovery）、**Dirsearch**（directoryEnumerate）、**Hydra**（defaultcredentialsbrute force）、**ScoutSuite**（cloudconfigurationaudit）。

---

## Methodology / Methodology

### Attack Chain / Attack Chain

```
[1] Service Enumeration      [2] Default Credential Testing   [3] Header Analysis
    - nmap 版本探测              - 默认用户名/密码字典             - 检查安全 Header
    - whatweb 指纹识别            - Hydra/medusa 爆破              - CSP 策略审计
    - 端口与服务映射              - 管理接口默认凭证               - Cookie 属性检查
         |                           |                              |
         v                           v                              v
[4] Error Page Probing       [5] Config File Discovery
    - 触发详细错误响应            - 目录列表检测
    - 路径遍历探测                - 备份文件发现
    - 堆栈跟踪分析                - 版本控制文件暴露
    - 框架版本识别                - .env / .git / .svn 泄露
```

### Defense Perspective / Defense Perspective

| Defense Measure | Description | Priority |
|----------|------|--------|
| Server Hardening Guide | follow CIS Benchmark / DISA STIG foroperationsystem、inintervalpieceperformhardening | CRITICAL |
| Automated Config Scanning | will Nikto、testssl.sh、ScoutSuite integrationto CI/CD pipeline，eachtimedeploymentautomated Detect | HIGH |
| Security Headers | deploymentcomplete security Header collection（HSTS、CSP、X-Frame-Options、X-Content-Type-Options） | HIGH |
| Remove Default Installs | deletedefaultpage、exampleapplication、testingaccount、admin backenddefaultentry point | CRITICAL |
| Error Handling Policy | productionenvironmentunifiederrorpage，prohibitstacktrackingandinternalinformationleakage | HIGH |
| Least Privilege Services | disablenotnecessary serviceandport，followleast privilegeoriginalthen | HIGH |

---

## Practical Steps / Practical Steps

### Step 1: Nikto Web Scan

use Nikto performautomated Web configurationScan，Detectdefaultfile、dangerousconfigurationandoverwhen component。

### Step 2: HTTP security Header check

obtainandreview HTTP response Header，verifycriticalsecurity Header iswhetherexistsandconfigurationcorrect。

### Step 3: defaultcredentialsbrute force

use Hydra forloginformanddatabaseserviceperformdefaultcredentialstesting。

### Step 4: Verbose Error exploit

throughsendmalformedrequest、superlengthparameter、illegal HTTP methodtriggerdetailed errorinformation。

### Step 5: directorylistandsensitivefilediscovery

Detectdirectorylistenablesituation，discoveryversioncontrolfileandenvironmentconfigurationfileleakage。

> **See payloads.md for detailed payloads, and test-cases.md for complete test checklist。**

---

## Automation and Scripting

Automated misconfiguration scanning should be integrated into CI/CD pipelines to catch regressions before deployment. Shell scripts wrapping Nikto, testssl.sh, and curl header checks can produce machine-readable JSON reports that trigger failures on missing security headers or weak TLS configurations. Nuclei templates provide a continuously updated library of misconfiguration detection patterns, enabling efficient batch scanning across large inventories of targets.

## Common Pitfalls

A frequent oversight in security misconfiguration audits is checking only the application layer while ignoring infrastructure defaults — database servers, message queues, and container orchestration platforms often ship with permissive defaults that go unmodified in production. Another common mistake is treating security headers as a one-time configuration task; framework upgrades and CDN changes can silently remove or weaken previously configured headers. Regular automated validation prevents these regressions.

## Detection Methods

Effective misconfiguration detection combines active probing with passive analysis. Active methods include sending deliberately malformed requests to trigger verbose error pages, enumerating default installation paths (`/admin/`, `/phpmyadmin/`, `/server-status/`), and testing default credential lists against discovered login forms. Passive methods analyze HTTP response headers for missing or weak security configurations, inspect TLS certificate chains for expired or weak intermediates, and review DNS records for unnecessary information disclosure.

---

## Hacker Laws / Hacker Laws

1. **Obscurity Is Not Security (obfuscationnotissecurity )** -- hidemanagemententry point、usenon-standardport、notexposureversionnumberandnotcanblockattacker。真正 security from correct configurationandeffective accesscontrol，andnon依靠attackerfindnottotarget。any exposureinnetworkon serviceallwillbyautomated Scantooldiscovery。

2. **Minimize Attack Surface (minimumizeattack surface)** -- eachaopenport、eacharunservice、eachainstall componentallis潜inattack surface。deletenotnecessarysuccesscan、disablenot useport、uninstallexampleapplication -- attack surface越small，security risk越low。security configuration coretheniscontinuousreduceattack surface。

3. **Defense in Depth (defense in depth)** -- notcanonlydependencysomealayerconfiguration。HSTS preventdowngradelevel、CSP limitationscriptexecute、X-Frame-Options blockclickjacking、WAF providesadditionalfilter -- eachalayerallisitsotherlayer backup。whensomealayerconfiguration失误when ，itsotherlayer仍canprovidesprotect。

---

## Learning Resources / Learning Resources

 **Skill supplementary files**: payloads.md, test-cases.md
 **Related Skills**: skills/logging-monitoring/SKILL.md, skills/container-security/SKILL.md

 **internalmaterial (this workspace)**:
 - `guides/security_misconfiguration_complete_guide.md` -- security configurationerrorcompleteguide（directoryEnumerate、informationleakage、cloud storageconfiguration、automated ScanTool）

 **External Resources**:
 - [OWASP Top 10 - A02:2025 Security Misconfiguration](https://owasp.org/Top10/A02_2021-Security_Misconfiguration/)
 - [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
 - [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/) -- operationsystemandinintervalpiecehardeningbase准
 - [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/) -- TLS bestpracticeconfigurationgeneratetool
 - [SecurityHeaders.com](https://securityheaders.com/) -- online HTTP security Header Detect
 - [HackTricks - Pentesting Methodology](https://book.hacktricks.xyz/pentesting-web/pentesting-web)

---

## Misconfiguration Categories

Understanding misconfiguration types helps prioritize testing. Each category has distinct detection methods and remediation strategies.

| Category | OWASP Reference | Detection Complexity | Exploit Impact |
|----------|----------------|---------------------|----------------|
| Default Credentials | A02:2025 | Low (automated) | Critical (full system access) |
| Unnecessary Services | A02:2025 | Low (port scanning) | High (attack surface expansion) |
| Verbose Error Messages | A04:2021 | Low (manual probing) | Medium (information disclosure) |
| Missing Security Headers | A02:2025 | Low (curl/nmap) | Medium (XSS/clickjacking enablement) |
| Directory Listing | A02:2025 | Low (curl/ffuf) | High (source code, config exposure) |
| TLS/SSL Weaknesses | A02:2025 | Medium (testssl.sh) | High (MITM, credential interception) |
| Cloud Storage Exposure | A02:2025 | Medium (cloud tools) | Critical (data breach) |
| CORS Misconfiguration | A02:2025 | Medium (manual testing) | High (cross-origin data theft) |
| Cookie Misconfiguration | A02:2025 | Low (curl) | Medium (session hijacking) |
| Debug Mode Enabled | A02:2025 | Low (ffuf/nuclei) | Critical (RCE, secrets exposure) |

**Testing priority**: Start with default credentials and debug endpoints (highest ROI), then move to headers and TLS, then cloud storage and CORS.

---

## Hardening Checklist

Use this checklist to verify that a system is properly hardened against common misconfigurations. Each item maps to a specific remediation action.

### Network Layer
- [ ] All unnecessary ports closed (only 80, 443 for web servers)
- [ ] Management interfaces (SSH, RDP, databases) restricted to internal IPs
- [ ] Firewall rules follow default-deny policy
- [ ] No services running on non-standard ports (scan all 65535 ports to verify)
- [ ] ICMP responses disabled where not needed

### Application Layer
- [ ] Debug mode disabled in production (`APP_DEBUG=false`, `DEBUG=False`, `display_errors=Off`)
- [ ] Default pages removed (Apache test page, Nginx default, Tomcat welcome)
- [ ] Default credentials changed on all services
- [ ] Directory listing disabled globally
- [ ] Custom error pages configured (no stack traces)
- [ ] Admin panels require authentication and IP restriction

### HTTP Security Headers
- [ ] `Strict-Transport-Security` (HSTS) with `includeSubDomains` and `preload`
- [ ] `Content-Security-Policy` with strict `default-src` and `script-src`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options: DENY` or `SAMEORIGIN`
- [ ] `Referrer-Policy: strict-origin-when-cross-origin`
- [ ] `Permissions-Policy` restricting camera, microphone, geolocation

### TLS/SSL
- [ ] TLS 1.2 minimum; TLS 1.0 and 1.0 disabled
- [ ] Strong cipher suites only (no RC4, no DES, no 3DES)
- [ ] Certificate valid and not expired
- [ ] HSTS header present and configured
- [ ] Certificate chain complete (no missing intermediates)

### File and Data Protection
- [ ] `.git`, `.svn`, `.env` files not accessible via web
- [ ] Backup files (`.bak`, `.old`, `.sql`) not in web root
- [ ] Sensitive directories (`/admin`, `/backup`, `/config`) access-controlled
- [ ] Upload directories do not allow script execution
- [ ] No sensitive data in client-accessible JavaScript files

---

## Configuration Auditing Tools

Automated configuration auditing catches misconfigurations at scale. Integrate these tools into CI/CD pipelines and regular security reviews.

| Tool | Scope | Output Format | CI/CD Integration |
|------|-------|--------------|-------------------|
| **Nikto** | Web server configuration | HTML, CSV, XML | Yes (exit codes) |
| **testssl.sh** | TLS/SSL configuration | JSON, CSV, HTML | Yes |
| **Nuclei** | Broad misconfiguration templates | JSON, SARIF | Yes |
| **ScoutSuite** | Cloud configuration audit | HTML report | Limited |
| **Prowler** | AWS CIS compliance | JSON, CSV, HTML | Yes |
| **Lynis** | OS hardening audit | Plain text report | Yes |
| **OpenSCAP** | OS compliance (DISA STIG, CIS) | HTML, XCCDF | Yes |
| **Checkov** | Infrastructure-as-Code scanning | JSON, SARIF | Yes (native) |
| **tfsec** | Terraform security scanning | JSON, SARIF | Yes (native) |

**Automation pipeline example:**

```bash
#!/bin/bash
# config-audit.sh — Run automated configuration audit
TARGET="$1"
REPORT_DIR="reports/$(date +%Y%m%d)"

mkdir -p "$REPORT_DIR"

# Web server audit
nikto -h "https://$TARGET" -o "$REPORT_DIR/nikto.html" -Format htm

# TLS audit
testssl.sh --json-pretty "$TARGET:443" > "$REPORT_DIR/tls.json"

# Header audit (custom script)
curl -sI "https://$TARGET" | grep -iE "strict-transport|content-security|x-frame|x-content-type" \
  > "$REPORT_DIR/headers.txt"

# Nuclei misconfiguration templates
nuclei -u "https://$TARGET" -t misconfiguration/ -o "$REPORT_DIR/nuclei.txt"

echo "[+] Audit complete. Reports in $REPORT_DIR/"
```

---

## Baseline Comparison

Configuration drift occurs when deployed systems deviate from the approved security baseline. Regular baseline comparison catches unauthorized changes and configuration regressions.

**Baseline comparison workflow:**

1. **Create baseline**: After hardening a system, capture a snapshot of all security-relevant configurations
2. **Store securely**: Save the baseline in version control or a secure document store
3. **Schedule comparisons**: Run weekly or after every deployment
4. **Alert on drift**: Any deviation from the baseline triggers an investigation

```bash
#!/bin/bash
# Baseline creation script
BASELINE_DIR="/opt/security-baselines/$(hostname)/$(date +%Y%m%d)"
mkdir -p "$BASELINE_DIR"

# Capture security-relevant configurations
cp /etc/apache2/apache2.conf "$BASELINE_DIR/" 2>/dev/null
cp /etc/nginx/nginx.conf "$BASELINE_DIR/" 2>/dev/null
cp /etc/ssh/sshd_config "$BASELINE_DIR/" 2>/dev/null
cp /etc/mysql/my.cnf "$BASELINE_DIR/" 2>/dev/null

# Capture security headers
curl -sI "https://$(hostname)" > "$BASELINE_DIR/security_headers.txt"

# Capture open ports
nmap -sT -O "$(hostname)" > "$BASELINE_DIR/open_ports.txt"

# Capture TLS configuration
testssl.sh --quiet "$(hostname):443" > "$BASELINE_DIR/tls_config.txt"

# Capture installed packages
dpkg -l > "$BASELINE_DIR/packages.txt" 2>/dev/null
rpm -qa > "$BASELINE_DIR/packages.txt" 2>/dev/null

echo "[+] Baseline saved to $BASELINE_DIR"
echo "[+] Run baseline-diff.sh to compare against this baseline"
```

```bash
#!/bin/bash
# Baseline comparison script
CURRENT="/tmp/current_baseline"
BASELINE="/opt/security-baselines/$(hostname)/latest"

# Create current snapshot (same commands as baseline creation)
# ... (same capture commands)

# Compare
echo "=== Security Header Changes ==="
diff "$BASELINE/security_headers.txt" "$CURRENT/security_headers.txt"

echo "=== Open Port Changes ==="
diff "$BASELINE/open_ports.txt" "$CURRENT/open_ports.txt"

echo "=== Package Changes ==="
diff "$BASELINE/packages.txt" "$CURRENT/packages.txt"
```
