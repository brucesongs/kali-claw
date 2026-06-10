# Filesystem Anti-Forensics Guide

## Introduction

Filesystem anti-forensics encompasses techniques for securely deleting data, wiping residual artifacts from filesystem metadata structures, and ensuring that forensic tools cannot recover evidence of file existence or content. This guide covers secure deletion tools (shred, wipe), slack space wiping, MFT and inode metadata manipulation, and comprehensive forensic artifact cleanup strategies.

Understanding filesystem anti-forensics requires deep knowledge of how filesystems store and manage data. Files are not simply "present" or "absent" on disk -- they leave traces in directory entries, allocation tables, journal logs, metadata structures (MFT on NTFS, inodes on ext4), and in the unallocated space between active files. Effective anti-forensics must address all of these data surfaces.

---

## 1. Secure File Deletion with shred

### How shred Works

shred operates by overwriting the target file's data blocks with multiple passes of random data, optionally followed by a zero-fill pass to mask the overwrite activity. The key parameter is the number of overwrite passes (`-n`), which determines how thoroughly the original data is destroyed.

```bash
# Standard secure deletion: 5 random passes + 1 zero pass (-z) + verbose (-v) + force (-f)
shred -vfz -n 5 /tmp/sensitive_file.txt

# Fast mode: 3 passes (sufficient for most testing scenarios)
shred -vfz -n 3 /tmp/tools/payload.exe

# Maximum paranoia: 35 passes (Gutmann method rationale, though modern drives rarely need this)
shred -vfz -n 35 /tmp/critical_evidence.bin

# Delete with truncate: shrinks file to zero length before unlinking
shred -vfzu -n 5 /tmp/engagement_data.dat
```

### Filesystem Limitations

shred's effectiveness depends heavily on the underlying storage technology and filesystem:

| Storage Type | shred Effectiveness | Notes |
|-------------|--------------------|----|
| HDD (magnetic) | HIGH | Direct overwrite of physical sectors |
| SSD (Flash) | LOW-MEDIUM | Wear leveling may write to different pages; original data persists |
| Btrfs/ZFS (CoW) | LOW | Copy-on-write writes to new blocks; original blocks may persist |
| ext4 (journaling) | MEDIUM | Journal may contain metadata about deleted files |
| NTFS | MEDIUM | MFT entries and journal ($LogFile) may retain metadata |
| Network filesystems | VERY LOW | No guarantee data is overwritten on remote storage |

For SSDs, the only reliable secure deletion method is the ATA Secure Erase command (`hdparm --security-erase`), which triggers the drive's firmware to erase all flash pages. For copy-on-write filesystems, consider destroying the entire volume rather than individual files.

### Recursive Secure Deletion

```bash
# Securely delete all files in a directory tree
find /tmp/engagement_artifacts/ -type f -exec shred -vfz -n 3 {} \;

# Remove empty directories after shredding
find /tmp/engagement_artifacts/ -type d -empty -delete

# Alternative: wipe entire directory at once
wipe -rfci /tmp/engagement_artifacts/
```

---

## 2. Secure Wiping with wipe

wipe provides directory-level secure deletion that handles entire directory trees, symlinks, and special files. It overwrites files using a random pattern followed by a configurable number of passes.

```bash
# Recursive wipe with 4 passes (faster than default 34)
wipe -rfci -Q 4 /tmp/sensitive_directory/

# Wipe a partition (authorized targets only)
wipe -fcki /dev/sdb1

# Wipe with verification (checks last pass is all zeros)
wipe -rfci -Q 3 -F /tmp/tools/
```

---

## 3. Slack Space Wiping

When a file is written to disk, the filesystem allocates space in blocks (typically 4KB on ext4, up to 64KB on NTFS). If a file is smaller than one block, the remaining bytes in that block ("slack space") retain whatever data was previously stored there. This slack space is a goldmine for forensic examiners.

### Identifying and Wiping Slack Space

```bash
# Extract all slack space from a filesystem image using SleuthKit
blkls -s /dev/sda1 > slack_space.raw

# Search slack space for sensitive strings
strings slack_space.raw | grep -iE "password|secret|token|key|credential"

# Wipe slack space by writing zeros to file tails
# Create a file that fills the entire filesystem, then delete it
dd if=/dev/zero of=/tmp/fill_slack.tmp bs=1M
sync
shred -vfz -n 1 /tmp/fill_slack.tmp
rm -f /tmp/fill_slack.tmp

# Alternative: use bmap to specifically target slack space
bmap --mode wipe /tmp/legitimate_file.txt
```

---

## 4. MFT and Inode Metadata Manipulation

### NTFS MFT (Master File Table)

Every file on an NTFS volume has an entry in the MFT containing two sets of timestamps:

1. **$STANDARD_INFORMATION** - Modified, Accessed, Created, Entry Modified (MACE). This is the timestamp that Windows Explorer displays and that most tools modify.
2. **$FILE_NAME** - Stored in the directory index. This timestamp is harder to modify and is the forensic examiner's ground truth.

When an attacker uses timestomp to modify file timestamps, only the $STANDARD_INFORMATION attributes change. Forensic examiners compare both attribute sets to detect timestamp manipulation.

```bash
# In Meterpreter session: view current MACE timestamps
timestomp target_file.exe -v

# Copy timestamps from a legitimate system file
timestomp malicious.dll -f C:\Windows\System32\kernel32.dll

# Set specific timestamps to blend with surrounding files
timestomp payload.exe -z "03/15/2025 14:22:17"
```

### ext4 Inode Metadata

On ext4 filesystems, each file's inode stores three timestamps: atime (access), mtime (modification), and ctime (change). The ctime is updated automatically by the kernel whenever any metadata changes, and it cannot be directly set by userspace tools. This makes ctime a reliable indicator of when a file was last modified.

```bash
# View inode timestamps
stat /etc/passwd

# Modify atime and mtime (but ctime will update to current time)
touch -t 202401010830 /tmp/modified_file.txt

# Check if debugfs reveals additional information
debugfs -R "stat <12>" /dev/sda1  # where 12 is the inode number

# Use faketime to manipulate ctime (changes system clock perception)
faketime '2024-01-01 08:30:00' touch /tmp/file.txt
```

### Journal Artifact Cleanup

Journaling filesystems (ext4, NTFS) maintain logs of recent metadata changes. Even after securely deleting files and modifying timestamps, the journal may contain records of the original operations.

```bash
# ext4 journal: check for deleted file references
debugfs -R "logdump" /dev/sda1 | grep -i "deleted\|unlink"

# Force journal commit to overwrite older entries
sync
echo 3 > /proc/sys/vm/drop_caches

# NTFS journal ($LogFile): requires specialized tools to parse
# The journal contains records of all recent file operations
```

---

## 5. Comprehensive Forensic Artifact Cleanup

A complete anti-forensic cleanup must address every surface where engagement artifacts may persist:

```bash
#!/bin/bash
# Comprehensive filesystem artifact cleanup script
# AUTHORIZED TESTING ENVIRONMENTS ONLY

echo "[1/6] Shredding engagement files..."
find /tmp/engagement/ -type f -exec shred -vfz -n 3 {} \;
find /tmp/engagement/ -type d -empty -delete

echo "[2/6] Wiping swap space..."
swapoff -a
shred -vfz -n 2 /dev/sda2  # adjust to actual swap partition
mkswap /dev/sda2

echo "[3/6] Clearing temp directories..."
rm -rf /tmp/* /var/tmp/* 2>/dev/null

echo "[4/6] Wiping bash history..."
shred -vfz -n 3 ~/.bash_history 2>/dev/null
history -c && history -w
unset HISTFILE

echo "[5/6] Clearing system caches..."
sync
echo 3 > /proc/sys/vm/drop_caches

echo "[6/6] Verifying cleanup..."
echo "Remaining temp files:"
find /tmp/ -type f 2>/dev/null | head -10
echo "Swap status:"
swapon -s
```

---

## References

- **shred Manual**: `man shred` or https://man7.org/linux/man-pages/man1/shred.1.html -- Complete documentation on overwrite passes, filesystem limitations, and SSD considerations
- **wipe Manual**: `man wipe` -- Secure file wiping with configurable pass counts
- **SleuthKit blkls**: https://sleuthkit.org/sleuthkit/ -- Tool for extracting and analyzing slack space and unallocated space
- **NIST SP 800-88 Rev. 1**: https://csrc.nist.gov/publications/detail/sp/800-88/rev-1/final -- Guidelines for media sanitization including clear, purge, and destroy methods
- **NTFS MFT Forensics**: https://docs.microsoft.com/en-us/windows/win32/fileio/ -- Windows filesystem internals including MFT structure and timestamp attributes
