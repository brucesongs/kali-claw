# Anti-Forensics Test Cases

> This file is a companion to `SKILL.md`, containing structured test case checklists.

---

## Test Case Statistics

| Category | Count | Severity Coverage |
|----------|-------|-------------------|
| A. Secure File Deletion | 1 | CRITICAL |
| B. Encrypted Volume Creation | 1 | CRITICAL |
| C. Log Cleaning | 1 | HIGH |
| D. Timestamp Manipulation | 1 | HIGH |
| E. Steganographic Hiding | 1 | HIGH |
| F. bulk_extractor Detection Testing | 1 | HIGH |
| G. Comprehensive Cleanup Verification | 1 | CRITICAL |
| H. Network Trace Cleanup | 1 | HIGH |
| **Total** | **8** | **CRITICAL: 3, HIGH: 5** |

---

## A. Secure File Deletion

### TC-AF-001: Secure File Deletion and Recovery Verification

| Field | Value |
|------|-------|
| **ID** | TC-AF-001 |
| **Category** | A. Secure File Deletion |
| **Severity** | CRITICAL |
| **Objective** | Verify that securely deleted files are unrecoverable by standard forensic recovery tools, confirming overwrite effectiveness
| **Title** | Secure File Deletion and Recovery Verification |
| **Description** | Verify that files securely deleted with shred cannot be recovered by standard forensic tools (foremost, scalpel, bulk_extractor). Confirm that overwrite passes effectively destroy file content. |
| **Prerequisites** | Test disk image with known files to be shredded; foremost and bulk_extractor installed |
| **Test Steps** | 1. Create test files with known content on a test filesystem: `echo "TOPSECRET_DATA_$(date +%s)" > /tmp/test_volume/secret.txt` |
| | 2. Record the original file hash: `sha256sum /tmp/test_volume/secret.txt` |
| | 3. Securely delete with shred: `shred -vfz -n 5 /tmp/test_volume/secret.txt` |
| | 4. Create a disk image of the test volume: `dd if=/dev/loop0 of=post_shred.dd bs=4K` |
| | 5. Attempt file recovery with foremost: `foremost -t all -i post_shred.dd -o /tmp/recovery/` |
| | 6. Attempt feature extraction with bulk_extractor: `bulk_extractor -o /tmp/be_output post_shred.dd` |
| | 7. Search for known content string: `strings post_shred.dd | grep "TOPSECRET_DATA"` |
| **Expected Results** | foremost recovery directory contains no files matching the original; bulk_extractor output contains no email/url/tcp features matching the test data; strings search returns no matches for the known content string; original hash cannot be verified against any recovered file. |
| **Related File** | `payloads.md` -> Secure File Deletion, `guides/filesystem-anti-forensics.md` |

### Remediation (Defense Perspective)

- Use full-disk encryption (LUKS, BitLocker) to ensure deleted data is not recoverable without the encryption key
- Implement SSD TRIM commands to ensure flash memory cells are properly cleared
- Deploy file integrity monitoring (AIDE, Tripwire) to detect anti-forensic file manipulation

---

## B. Encrypted Volume Creation

### TC-AF-002: Encrypted Volume Creation and Forensic Opacity

| Field | Value |
|------|-------|
| **ID** | TC-AF-002 |
| **Category** | B. Encrypted Volume Creation |
| **Severity** | CRITICAL |
| **Objective** | Verify that encrypted volumes prevent forensic tools from identifying or extracting stored content
| **Title** | Encrypted Volume Creation and Forensic Opacity Verification |
| **Description** | Verify that tcplay encrypted volumes prevent forensic tools from extracting the contents. Confirm that binwalk and bulk_extractor cannot identify files stored within the encrypted container. |
| **Prerequisites** | tcplay installed; loop device available; test files to store in encrypted volume |
| **Test Steps** | 1. Create a 50MB encrypted volume: `dd if=/dev/zero of=enc_vol bs=1M count=50 && losetup /dev/loop0 enc_vol` |
| | 2. Initialize tcplay volume: `tcplay -c -d /dev/loop0` (set test passphrase) |
| | 3. Map, format, and mount: `tcplay -m enc -d /dev/loop0 && mkfs.ext4 /dev/mapper/enc && mount /dev/mapper/enc /mnt/enc/` |
| | 4. Store test files: `cp /etc/passwd /mnt/enc/ && echo "SENSITIVE_$(date +%s)" > /mnt/enc/secret.txt` |
| | 5. Unmount and detach: `umount /mnt/enc/ && tcplay -u enc` |
| | 6. Scan the encrypted volume file with binwalk: `binwalk enc_vol` |
| | 7. Scan with bulk_extractor: `bulk_extractor -o /tmp/be_enc enc_vol` |
| | 8. Search for known content: `strings enc_vol | grep "SENSITIVE_"` |
| **Expected Results** | binwalk does not identify any file signatures within the encrypted volume; bulk_extractor does not extract email, URL, or text features containing the stored content; strings search returns no matches for "SENSITIVE_"; the volume appears as high-entropy random data. |
| **Related File** | `payloads.md` -> Disk/Volume Encryption, `guides/crypto-hide-data-destruction.md` |

### Remediation (Defense Perspective)

- Monitor for encrypted volume creation and mounting using OS-level auditing
- Detect tcplay and cryptsetup usage through process monitoring
- Use hardware-based full-disk encryption (SED/OPAL) to prevent software-level encryption evasion

---

## C. Log Cleaning

### TC-AF-003: Log Entry Removal and Continuity Verification

| Field | Value |
|------|-------|
| **ID** | TC-AF-003 |
| **Category** | C. Log Cleaning |
| **Severity** | HIGH |
| **Objective** | Verify that log entry removal maintains log file continuity to avoid detection by automated analysis tools
| **Title** | Log Entry Removal and Continuity Verification |
| **Description** | Verify that logtamper removes specified log entries. Evaluate whether the cleaned log files maintain sufficient continuity to avoid detection by automated log analysis tools. |
| **Prerequisites** | Test system with populated auth.log containing known test entries; logtamper installed |
| **Test Steps** | 1. Generate test log entries: `logger -t sshd "Accepted password for testuser from 192.168.100.50"` (multiple entries with timestamps) |
| | 2. Record the original log line count: `wc -l /var/log/auth.log` |
| | 3. Remove entries for test IP: `logtamper -f /var/log/auth.log -r "192.168.100.50"` |
| | 4. Verify removal: `grep "192.168.100.50" /var/log/auth.log` (should return nothing) |
| | 5. Check new line count: `wc -l /var/log/auth.log` |
| | 6. Test for timestamp gaps: `awk 'NR>1 {split($3,t,":"); split(prev,pt,":"); gap=(t[1]*3600+t[2]*60+t[3])-(pt[1]*3600+pt[2]*60+pt[3]); if(gap>300) print "GAP detected at line "NR} {prev=$3}' /var/log/auth.log` |
| | 7. Test log integrity with logcheck or similar: `logcheck -S -o /tmp/logcheck.out` |
| **Expected Results** | grep returns no matches for the removed IP; the log file has fewer lines than the original; timestamp gaps may be detectable depending on the density of removed entries; logcheck flags anomalies if entries were removed from high-density time periods. |
| **Related File** | `payloads.md` -> Log Cleaning, `guides/log-tamper-timestamp.md` |

### Remediation (Defense Perspective)

- Forward logs to a centralized, write-once SIEM or syslog server in real-time
- Enable immutable logging (chattr +i on log files, or journald with SystemMaxUse)
- Use log hashing (logcheck, OSSEC) to detect tampering and gap anomalies

---

## D. Timestamp Manipulation

### TC-AF-004: File Timestamp Forging and Forensic Detection

| Field | Value |
|------|-------|
| **ID** | TC-AF-004 |
| **Category** | D. Timestamp Manipulation |
| **Severity** | HIGH |
| **Objective** | Verify timestamp manipulation effectiveness and evaluate whether forensic analysis tools can detect the forgery
| **Title** | File Timestamp Forging and Forensic Detection Testing |
| **Description** | Verify that timestamp manipulation tools successfully modify file MAC timestamps. Evaluate whether forensic analysis tools (SleuthKit, analyzeMFT) can detect the manipulation through timestamp inconsistencies. |
| **Prerequisites** | Test filesystem with NTFS partition (for timestomp testing); Metasploit framework with timestomp module; SleuthKit installed |
| **Test Steps** | 1. Create a test file with known creation time: `touch -t 202606011200 test_file.txt` |
| | 2. Record original timestamps: `stat test_file.txt` and `fls -m "/" -o 2048 test_image.dd` |
| | 3. Forge timestamps using touch (Linux): `touch -t 202401010830 test_file.txt` |
| | 4. Verify modification: `stat test_file.txt` (should show forged timestamps) |
| | 5. Check if debugfs reveals original timestamps: `debugfs -R "stat <inode>" /dev/sda1` |
| | 6. For NTFS: use timestomp via Meterpreter to modify $STANDARD_INFORMATION |
| | 7. Compare $STANDARD_INFORMATION vs $FILE_NAME timestamps using analyzeMFT |
| **Expected Results** | stat shows the forged timestamps; on ext4, debugfs may reveal the actual change time (ctime) since it cannot be directly modified via touch; on NTFS, analyzeMFT reveals a discrepancy between $STANDARD_INFORMATION and $FILE_NAME timestamps, demonstrating that naive timestomp is detectable by comparing both attributes. |
| **Related File** | `payloads.md` -> Timestamp Manipulation, `guides/log-tamper-timestamp.md` |

### Remediation (Defense Perspective)

- Use NTFS $FILE_NAME attribute comparison to detect $STANDARD_INFORMATION timestomp
- Deploy file system auditing that logs timestamp changes with the original values
- Use event logging that captures ctime changes separately from mtime/atime

---

## E. Steganographic Hiding

### TC-AF-005: Steganographic Data Hiding and Detection Testing

| Field | Value |
|------|-------|
| **ID** | TC-AF-005 |
| **Category** | E. Steganographic Hiding |
| **Severity** | HIGH |
| **Objective** | Verify steganographic embedding hides data without visual detection and test detection tool effectiveness
| **Title** | Steganographic Data Hiding and Detection Testing |
| **Description** | Verify that steghide successfully embeds data into carrier files without visually detectable changes. Test whether steganographic detection tools (stegdetect) and forensic analysis can identify the hidden payload. |
| **Prerequisites** | steghide installed; test carrier image (JPEG); stegdetect installed for verification testing |
| **Test Steps** | 1. Prepare a test payload: `echo "CLASSIFIED_ENGAGEMENT_DATA_$(date +%s)" > /tmp/payload.txt` |
| | 2. Record carrier file properties: `sha256sum carrier.jpg && file carrier.jpg && identify carrier.jpg` |
| | 3. Embed payload: `steghide embed -cf carrier.jpg -ef /tmp/payload.txt -p "test_passphrase"` |
| | 4. Compare file sizes: `ls -la carrier.jpg` (should be very similar size) |
| | 5. Verify visual integrity: `compare original.jpg carrier.jpg diff.png` (ImageMagick) |
| | 6. Test extraction: `steghide extract -sf carrier.jpg -p "test_passphrase" -f /tmp/recovered.txt` |
| | 7. Verify recovered content: `cat /tmp/recovered.txt` |
| | 8. Test detection with stegdetect: `stegdetect carrier.jpg` |
| | 9. Test detection with statistical entropy analysis: `dd if=carrier.jpg bs=1 skip=1000 count=10000 | ent` |
| **Expected Results** | Embedded file size is within 1-2% of original; ImageMagick diff shows minimal visual changes; steghide extraction recovers exact payload content; stegdetect may or may not flag the file depending on embedding parameters; entropy analysis of the carrier remains within normal JPEG ranges (7.5-7.9 for compressed image data). |
| **Related File** | `payloads.md` -> Steganographic Hiding, `guides/crypto-hide-data-destruction.md` |

### Remediation (Defense Perspective)

- Deploy steganalysis tools (stegdetect, StegExpose) in automated scanning pipelines
- Monitor for steghide and stegseek process execution on endpoints
- Implement DLP (Data Loss Prevention) to detect unusual file size changes in carrier media

---

## F. bulk_extractor Detection Testing

### TC-AF-006: bulk_extractor Anti-Forensic Effectiveness Validation

| Field | Value |
|------|-------|
| **ID** | TC-AF-006 |
| **Category** | F. bulk_extractor Detection Testing |
| **Severity** | HIGH |
| **Objective** | Validate anti-forensic cleanup effectiveness by comparing pre-cleanup and post-cleanup forensic extraction results
| **Title** | bulk_extractor Anti-Forensic Effectiveness Validation |
| **Description** | Use bulk_extractor as a forensic validation tool to verify that anti-forensic cleanup was effective. Compare pre-cleanup and post-cleanup extraction results to confirm no recoverable artifacts remain. |
| **Prerequisites** | Test disk image with known artifacts; bulk_extractor installed; shred and logtamper available |
| **Test Steps** | 1. Create baseline extraction: `bulk_extractor -o /tmp/be_before test_image.dd` |
| | 2. Catalog baseline artifacts: `wc -l /tmp/be_before/email.txt /tmp/be_before/url.txt /tmp/be_before/tcp.txt` |
| | 3. Perform cleanup: shred sensitive files, clean logs, wipe slack space |
| | 4. Create post-cleanup image: `dd if=/dev/loop0 of=post_cleanup.dd bs=4K` |
| | 5. Run bulk_extractor on cleaned image: `bulk_extractor -o /tmp/be_after post_cleanup.dd` |
| | 6. Compare results: `diff /tmp/be_before/email.txt /tmp/be_after/email.txt` |
| | 7. Search for known test strings: `grep -r "test_marker" /tmp/be_after/` |
| | 8. Verify no file signatures remain: `cat /tmp/be_after/tcp.txt | head -20` |
| **Expected Results** | Post-cleanup bulk_extractor output has significantly fewer extracted features than the baseline; no test marker strings appear in the post-cleanup extraction; email and URL features from the test data are absent; the diff shows specific lines removed corresponding to the cleaned artifacts. Some residual data in unallocated space may persist depending on filesystem type and cleanup thoroughness. |
| **Related File** | `payloads.md` -> Anti-Forensic Countermeasures Testing, `guides/filesystem-anti-forensics.md` |

### Remediation (Defense Perspective)

- Establish forensic baselines of all systems before engagements for accurate comparison
- Use hardware write-blockers when imaging to prevent contamination
- Deploy automated forensic scanning (bulk_extractor scheduled runs) to detect cleanup attempts

---

## G. Comprehensive Cleanup Verification

### TC-AF-007: End-to-End Anti-Forensic Cleanup Validation

| Field | Value |
|------|-------|
| **ID** | TC-AF-007 |
| **Category** | G. Comprehensive Cleanup Verification |
| **Severity** | CRITICAL |
| **Objective** | Perform a complete anti-forensic cleanup cycle and validate using multiple forensic tools that no engagement artifacts remain
| **Title** | End-to-End Anti-Forensic Cleanup Validation |
| **Description** | Perform a complete anti-forensic cleanup cycle including file shredding, log cleaning, timestamp restoration, and encrypted volume teardown. Validate the entire cleanup using multiple forensic tools to ensure no engagement artifacts remain. |
| **Prerequisites** | Isolated test environment with test engagement artifacts; full toolset available (shred, wipe, logtamper, steghide, tcplay, bulk_extractor, foremost, SleuthKit) |
| **Test Steps** | 1. Record pre-engagement baseline: timestamps of all files in target directories, log file hashes and line counts, disk image hash |
| | 2. Simulate engagement: create files, modify logs, mount encrypted volumes, embed steganographic data |
| | 3. Perform cleanup: (a) shred all dropped files with 5 passes, (b) remove log entries matching engagement indicators, (c) restore file timestamps from baseline, (d) unmount and detach encrypted volumes, (e) wipe swap and temp directories |
| | 4. Create post-cleanup disk image: `dd if=/dev/loop0 of=post_cleanup.dd bs=4K` |
| | 5. Run foremost recovery: `foremost -t all -i post_cleanup.dd -o /tmp/foremost_out/` |
| | 6. Run bulk_extractor: `bulk_extractor -o /tmp/be_final post_cleanup.dd` |
| | 7. Run SleuthKit timeline: `fls -r -m "/" -o 2048 post_cleanup.dd | mactime -b -` |
| | 8. Compare log hashes and line counts with baseline |
| | 9. Search for engagement-specific strings across the entire image |
| **Expected Results** | foremost recovers no engagement-related files; bulk_extractor output contains no engagement artifacts (IPs, email addresses, tool strings); SleuthKit timeline shows no anomalous file creation timestamps during the engagement window; log file line counts match or are close to baseline (accounting for legitimate system activity); no engagement-specific strings are found in the disk image. Residual artifacts in unallocated space or SSD wear-leveling cells may persist, which is documented as a known limitation. |
| **Related File** | `payloads.md` -> Comprehensive Cleanup Verification, all guides |

### Remediation (Defense Perspective)

- Maintain pre-engagement forensic baselines (disk images, file hashes, log snapshots)
- Use network-level logging (NetFlow, Zeek) that cannot be cleaned from the host
- Deploy EDR tools that maintain tamper-resistant telemetry even after local cleanup

---

## H. Network Trace Cleanup

### TC-AF-008: Network Anti-Forensic Trace Removal and Verification

| Field | Value |
|------|-------|
| **ID** | TC-AF-008 |
| **Category** | H. Network Trace Cleanup |
| **Severity** | HIGH |
| **Objective** | Verify that all network forensic traces including ARP cache entries, DNS records, firewall logs, and proxy logs are cleaned up after an engagement
| **Title** | Network Anti-Forensic Trace Removal and Verification |
| **Description** | Remove evidence of network activity from local and intermediate network devices, including ARP cache entries, local DNS caches, firewall rule traces, and connection logs |
| **Prerequisites** | Engagement network activity documented (connections made, IPs contacted, services accessed); access to local machine and any intermediate devices used during engagement |
| **Test Steps** | 1. Flush local ARP cache: `ip neigh flush all` |
| | 2. Clear local DNS cache: `systemd-resolve --flush-caches` or `service nscd restart` |
| | 3. Remove iptables rules added during engagement: `iptables -F; iptables -X; iptables -t nat -F; iptables -t nat -X` |
| | 4. Clear /proc/net entries: verify `cat /proc/net/tcp` shows no active engagement connections |
| | 5. Remove SSH known_hosts entries for target hosts: `ssh-keygen -R target_ip` |
| | 6. Clean browser and tool proxy/VPN connection logs |
| | 7. Verify no background processes remain: `ps aux | grep -E 'nmap|nikto|sqlmap|proxychains|chisel'` |
| | 8. Verify no listening sockets from engagement tools: `ss -tlnp | grep -E '4444|8080|1080'` |
| **Expected Results** | ARP cache shows no entries for engagement target IPs; DNS cache cleared; all iptables rules removed; no SSH host keys for target hosts in known_hosts; no engagement tool processes running; no leftover listening sockets from engagement tools |
| **Related File** | `payloads.md` -> Network Anti-Forensics |

### Remediation (Defense Perspective)

- Use centralized network logging (SIEM, NetFlow collector) that is not accessible from compromised hosts
- Implement persistent connection tracking on network devices that survives endpoint cleanup
- Deploy network-level forensic tools (Zeek, Suricata) with remote log aggregation
