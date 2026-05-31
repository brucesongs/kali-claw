# Disk Image Analysis Guide

> Practical reference for forensic disk image examination using Autopsy, Sleuth Kit, and related tools: timeline analysis, deleted file recovery, file carving, and evidence extraction from raw disk images.

## 1. Disk Image Acquisition and Verification

Before analysis, acquire a forensically sound image and verify its integrity.

```bash
# Create forensic image with dc3dd (enhanced dd with hashing)
dc3dd if=/dev/sda of=evidence.raw hash=sha256 log=acquisition.log

# Or use ewfacquire for E01 format (compressed, with metadata)
ewfacquire /dev/sda -t evidence -f encase6 -c deflate:best \
  -D "Case 2026-001" -e "Examiner Name" -N "Suspect Workstation"

# Verify image integrity
sha256sum evidence.raw
# Compare against hash recorded during acquisition

# Mount E01 images for analysis
ewfmount evidence.E01 /mnt/ewf/
# Creates /mnt/ewf/ewf1 as raw device

# List partitions in the image
mmls evidence.raw
# Output shows partition layout:
# 000: Meta  0000000000  0000000000  (Primary Table)
# 001: -----  0000000000  0000002047  Unallocated
# 002: NTFS   0000002048  0001026047  (Windows partition)
# 003: Linux  0001026048  0002050047  (Linux partition)
```

## 2. Filesystem Analysis with Sleuth Kit

```bash
# Determine filesystem type and details
fsstat -o 2048 evidence.raw
# Shows: filesystem type, block size, volume label, timestamps

# List files and directories (including deleted)
fls -r -o 2048 evidence.raw
# -r = recursive, -o = partition offset in sectors
# Deleted files shown with * prefix: * filename.txt

# List only deleted files
fls -r -d -o 2048 evidence.raw | grep -v "^d"

# Get file metadata by inode number
istat -o 2048 evidence.raw 12345
# Shows: timestamps (MACB), size, block allocation, permissions

# Extract a specific file by inode
icat -o 2048 evidence.raw 12345 > recovered_file.doc

# Search for specific filenames
fls -r -o 2048 evidence.raw | grep -i "password\|secret\|key\|wallet"

# Timeline of file activity (MAC times)
fls -r -m "/" -o 2048 evidence.raw > bodyfile.txt
mactime -b bodyfile.txt -d > timeline.csv
# Filter timeline to specific date range
mactime -b bodyfile.txt 2026-01-01..2026-03-15 > filtered_timeline.csv
```

## 3. Autopsy Workflow for Comprehensive Analysis

```bash
# Start Autopsy (GUI-based, built on Sleuth Kit)
autopsy &
# Access via browser: http://localhost:9999/autopsy

# Command-line alternative: create case structure
mkdir -p /cases/case001/{images,output,logs}
cp evidence.raw /cases/case001/images/

# Run Autopsy ingest modules via command line (Autopsy 4.x+)
# Key modules to enable:
# - Hash Lookup (against NSRL and known-bad hashsets)
# - Keyword Search (emails, URLs, credit cards)
# - Recent Activity (browser history, USB devices)
# - Email Parser
# - Encryption Detection
# - Interesting Files (by extension/pattern)

# Export Autopsy results for external processing
sqlite3 /cases/case001/autopsy.db \
  "SELECT name, parent_path, size, mtime FROM tsk_files WHERE dir_type=0"
```

## 4. Deleted File Recovery and Carving

```bash
# File carving with Scalpel (signature-based recovery)
# Configure /etc/scalpel/scalpel.conf - uncomment desired file types
scalpel -c /etc/scalpel/scalpel.conf -o /output/carved evidence.raw

# PhotoRec - recovers files regardless of filesystem
photorec /d /output/photorec evidence.raw
# Interactive: select partition, filesystem type, and output directory

# Foremost - another carving tool with built-in signatures
foremost -t pdf,doc,jpg,png,zip -i evidence.raw -o /output/foremost

# Bulk Extractor - extracts artifacts without parsing filesystem
bulk_extractor -o /output/bulk evidence.raw
# Produces: emails.txt, urls.txt, ccn.txt, telephone.txt, etc.

# Recover deleted files from ext4 using extundelete
extundelete --restore-all evidence.raw --output-dir /output/ext4_recovered

# Recover from NTFS using ntfsundelete
ntfsundelete -o 2048 evidence.raw -p 100 -t 3d
# -p 100 = 100% recoverable, -t 3d = deleted within 3 days
ntfsundelete -o 2048 evidence.raw -u -m "*.xlsx" -d /output/ntfs_recovered
```

## 5. Timeline Analysis and Super Timeline

```bash
# Create a comprehensive super timeline with log2timeline (Plaso)
log2timeline.py --storage-file timeline.plaso evidence.raw
# This parses ALL timestamp sources: filesystem, registry, logs, browsers

# Filter and output the timeline
psort.py -o l2tcsv timeline.plaso -w supertimeline.csv
# Filter by date range
psort.py -o l2tcsv timeline.plaso \
  "date > '2026-02-01' AND date < '2026-02-28'" -w february.csv

# Filter by specific data sources
psort.py -o l2tcsv timeline.plaso \
  "parser == 'winevtx' OR parser == 'prefetch'" -w execution.csv

# Analyze timeline for suspicious patterns
# Look for: file creation clusters, off-hours activity, anti-forensics
grep -i "timestomp\|ccleaner\|eraser\|sdelete" supertimeline.csv
grep "02:00:00\|03:00:00\|04:00:00" supertimeline.csv | head -50
```

## 6. Windows Artifact Extraction

```bash
# Extract Windows Registry hives
icat -o 2048 evidence.raw $(ifind -n "Windows/System32/config/SAM" \
  -o 2048 evidence.raw) > SAM
icat -o 2048 evidence.raw $(ifind -n "Windows/System32/config/SYSTEM" \
  -o 2048 evidence.raw) > SYSTEM
icat -o 2048 evidence.raw $(ifind -n "Windows/System32/config/SOFTWARE" \
  -o 2048 evidence.raw) > SOFTWARE

# Parse registry with RegRipper
regripper -r SAM -p samparse
regripper -r SYSTEM -p compname
regripper -r SOFTWARE -p winver

# Extract user password hashes
impacket-secretsdump -sam SAM -system SYSTEM LOCAL

# Parse prefetch files (program execution evidence)
find /mnt/evidence/Windows/Prefetch -name "*.pf" -exec \
  python3 prefetch_parser.py {} \;

# Extract browser history (SQLite databases)
sqlite3 "/mnt/evidence/Users/*/AppData/Local/Google/Chrome/User Data/Default/History" \
  "SELECT url, title, datetime(last_visit_time/1000000-11644473600,'unixepoch') FROM urls ORDER BY last_visit_time DESC LIMIT 50"
```

## 7. Linux Artifact Extraction

```bash
# Mount Linux partition read-only for analysis
mount -o ro,loop,offset=$((2048*512)) evidence.raw /mnt/linux

# Extract authentication logs
cat /mnt/linux/var/log/auth.log | grep -E "(Failed|Accepted|session opened)"

# Analyze bash history for all users
find /mnt/linux/home -name ".bash_history" -exec echo "=== {} ===" \; -exec cat {} \;
cat /mnt/linux/root/.bash_history

# Check crontabs for persistence
find /mnt/linux/var/spool/cron -type f -exec echo "=== {} ===" \; -exec cat {} \;
cat /mnt/linux/etc/crontab
ls /mnt/linux/etc/cron.d/

# Examine SSH artifacts
find /mnt/linux -name "authorized_keys" -exec echo "=== {} ===" \; -exec cat {} \;
find /mnt/linux -name "known_hosts" -exec echo "=== {} ===" \; -exec cat {} \;

# Check for suspicious SUID binaries
find /mnt/linux -perm -4000 -type f -exec ls -la {} \;

# Analyze systemd services for persistence
find /mnt/linux/etc/systemd/system -name "*.service" -newer \
  /mnt/linux/etc/os-release -exec echo "=== {} ===" \; -exec cat {} \;
```

## 8. Reporting and Hash Verification

```bash
# Generate file hash inventory for evidence
find /output -type f -exec sha256sum {} \; > evidence_hashes.txt

# Create a summary report of findings
echo "=== Disk Image Analysis Report ===" > report.txt
echo "Image: evidence.raw" >> report.txt
echo "SHA256: $(sha256sum evidence.raw | awk '{print $1}')" >> report.txt
echo "Analysis Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> report.txt
echo "" >> report.txt
echo "Partitions:" >> report.txt
mmls evidence.raw >> report.txt
echo "" >> report.txt
echo "Deleted Files Recovered: $(find /output -type f | wc -l)" >> report.txt
echo "Timeline Entries: $(wc -l < supertimeline.csv)" >> report.txt

# Verify no evidence was modified during analysis
sha256sum evidence.raw
# Must match original acquisition hash
```
