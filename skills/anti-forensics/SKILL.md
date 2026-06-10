---
name: anti-forensics
description: "Anti-forensics is the offensive counterpart to digital forensics."
origin: openclaw
version: "0.1.19"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
metadata:
  domain: forensics
  tool_count: 14
  guide_count: 3
  mitre: "TA0005-Defense Evasion"
---

# Anti-Forensics

> **Supplementary Files**:
> - `payloads.md` — Command reference covering secure file deletion, disk/volume encryption, log cleaning, timestamp manipulation, steganographic hiding, and anti-forensic countermeasure testing
> - `test-cases.md` — Structured test case list covering secure deletion verification, encrypted volume creation, log cleaning, timestamp manipulation, steganographic hiding, and bulk_extractor detection testing
> - `guides/filesystem-anti-forensics.md` — Deep dive into secure deletion, slack space wiping, MFT/inode manipulation, and forensic artifact cleanup
> - `guides/log-tamper-timestamp.md` — Deep dive into log tampering, timestamp manipulation, event log injection, and defeating timeline analysis
> - `guides/crypto-hide-data-destruction.md` — Deep dive into encrypted volumes, steganographic hiding, deniable encryption, and bulk_extractor effectiveness testing

## Summary

Anti Forensics skill domain covering forensics operations.

**Tools**: shred, wipe, tcplay, logtamper, timestomp, bulk_extractor, steghide, Real-Time Logging (+6 more)

**Domain**: forensics

**MITRE ATT&CK**: TA0005-Defense Evasion

## Description

Anti-forensics is the offensive counterpart to digital forensics. While the digital-forensics skill focuses on evidence collection and analysis, this skill covers the techniques attackers use to prevent evidence collection, corrupt evidence, or hide data from forensic examination. Understanding these techniques is essential for penetration testers who must simulate realistic attack scenarios and for defenders who need to know what anti-forensic artifacts to look for.

The agent has mastered secure file deletion with shred and wipe, encrypted volume management with tcplay (TrueCrypt/VeraCrypt compatible), log manipulation with logtamper, timestamp forging with timestomp, forensic artifact extraction with bulk_extractor (used defensively to test anti-forensic effectiveness), and steganographic data hiding with steghide.

## Use Cases

1. **Post-Exploitation Cleanup** - After completing a penetration test, securely remove dropped tools, modified configurations, and log entries to simulate how a real attacker would cover their tracks
2. **Data Exfiltration Channel Testing** - Use steganographic hiding and encrypted volumes to test whether the target organization's data loss prevention (DLP) and forensic capabilities can detect hidden data channels
3. **Forensic Readiness Assessment** - Test the effectiveness of an organization's forensic tools and procedures by attempting anti-forensic techniques against a controlled environment, then verifying what artifacts remain detectable
4. **Red Team Evasion Validation** - Validate that red team operations can achieve realistic anti-forensic objectives, ensuring blue team detection rules are tested against the latest evasion techniques
5. **Incident Response Training** - Create realistic scenarios where defenders must detect anti-forensic activity including timestamp manipulation, log cleaning, and steganographic data exfiltration

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **shred** | Secure file overwrite and deletion | `shred -vfz -n 5 secret.txt` |
| **wipe** | Secure directory and file wiping | `wipe -rfci /tmp/sensitive/` |
| **tcplay** | TrueCrypt/VeraCrypt compatible encrypted volumes | `tcplay -c -d /dev/loop0` |
| **logtamper** | Unix log file entry manipulation | `logtamper -f /var/log/auth.log -r "192.168.1.100"` |
| **timestomp** | NTFS MACE timestamp modification (Metasploit) | `timestomp secret.txt -m "01/01/2024 00:00:00"` |
| **bulk_extractor** | Forensic feature extraction (anti-forensic testing) | `bulk_extractor -o /output disk_image.dd` |
| **steghide** | Steganographic data embedding in media files | `steghide embed -cf photo.jpg -ef secret.txt` |

## Methodology

### Attack Chain

```
Pre-Operation               Active Operations              Post-Operation
(Encrypted Volume           (Log Manipulation,             (Secure Deletion,
 Setup, Stego Prep)         Timestamp Forging)              Stego Extraction)
       |                          |                              |
       v                          v                              v
                                  Verification
                                  (bulk_extractor scan
                                   to confirm no artifacts
                                   remain detectable)
```

**Phase Details**:

1. **Pre-Operation** - Create encrypted containers with tcplay for storing tools and exfiltrated data. Prepare steganographic carrier files. Establish a clean baseline of the target system's log state and timestamps for later restoration.
2. **Active Operations** - During the engagement, manipulate logs in real-time using logtamper to remove evidence of access. Forge file timestamps with timestomp to blend malicious files with legitimate ones. Use steganographic channels to exfiltrate data without triggering DLP alerts.
3. **Post-Operation Cleanup** - Securely delete all dropped tools, temporary files, and artifacts using shred and wipe. Restore log files to their pre-engagement state. Verify timestamps are consistent. Remove any traces of encrypted volume mounts.
4. **Verification** - Use bulk_extractor against the target disk image to confirm no recoverable artifacts remain. Test whether forensic timeline analysis can detect the engagement activities. Validate that steganographic carriers pass visual and statistical analysis.

## Practical Steps

### Step 1: Secure Data Destruction

Use shred to overwrite file contents with multiple passes of random data before deletion, making recovery impossible with standard forensic tools. Use wipe for recursive directory cleaning. Understand which filesystems and storage technologies (SSDs with wear leveling, copy-on-write filesystems like ZFS/Btrfs) reduce the effectiveness of these tools.

### Step 2: Encrypted Volume Management

Create and manage encrypted volumes with tcplay (TrueCrypt/VeraCrypt compatible) for plausible deniability and secure storage. Understand hidden volume creation, keyfile-based authentication, and how encrypted containers appear in forensic analysis.

### Step 3: Log Manipulation and Timestamp Forging

Use logtamper to selectively remove or modify log entries, and timestomp to forge file MAC timestamps. Understand the forensic artifacts these techniques leave behind (journal entries, NTFS $STANDARD_INFORMATION vs $FILE_NAME discrepancies, log sequence gaps).

### Step 4: Steganographic Data Hiding

Embed data within image and audio files using steghide to create covert exfiltration channels. Understand capacity limits, statistical detection methods, and how to choose carrier files that minimize detectability.

### Step 5: Anti-Forensic Effectiveness Testing

Use bulk_extractor and other forensic tools against the target environment to verify anti-forensic measures are effective. If bulk_extractor can still recover artifacts, iterate on cleanup techniques until the desired level of forensic resistance is achieved.

> **Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.**

## Defense Perspective

| Best Practice | Description | Priority |
|---------------|-------------|----------|
| **Real-Time Logging** | Forward logs to a remote, append-only syslog server that attackers cannot tamper with locally | CRITICAL |
| **File Integrity Monitoring** | Deploy FIM tools (AIDE, OSSEC, Wazuh) that detect file modifications and timestamp changes in real-time | CRITICAL |
| **Endpoint Detection and Response** | EDR agents capture process creation events before anti-forensics tools can modify or delete evidence | CRITICAL |
| **NTFS Dual Timestamp Comparison** | Compare $STANDARD_INFORMATION and $FILE_NAME attributes; timestomp only modifies the former, creating a detectable discrepancy | HIGH |
| **Secure Deletion Detection** | Monitor for shred/wipe process execution and high-entropy file writes that indicate secure deletion activity | HIGH |
| **Steganography Detection** | Deploy stegdetect and statistical analysis tools to identify carrier files with abnormal entropy patterns | MEDIUM |
| **Encrypted Volume Detection** | Monitor for tcplay/VeraCrypt/LUKS device mapping events and loop device creation | MEDIUM |

## Common Pitfalls

- **Ignoring SSD wear leveling and CoW filesystems**: shred and wipe are designed for magnetic media. On SSDs with wear leveling, Btrfs, or ZFS, overwritten data may persist in flash pages or filesystem snapshots. Always verify the underlying storage technology before relying on secure deletion tools.
- **Forgetting about swap, hibernation, and temp files**: Even after securely deleting the primary file, sensitive data may persist in swap partitions, hibernation files (hiberfil.sys), temporary directories, or application caches. A comprehensive cleanup must address all potential data leakage points.
- **Modifying timestamps without understanding forensic detection**: Timestomp only modifies the $STANDARD_INFORMATION timestamp on NTFS, leaving the $FILE_NAME timestamp unchanged. Forensic examiners routinely compare both attributes, making naive timestamp manipulation immediately detectable. Logtamper creates sequence gaps that automated timeline tools flag as anomalies.

## Automation and Scripting

Automate post-operation cleanup with scripts that chain secure deletion, log restoration, and timestamp normalization. Build a cleanup pipeline that: (1) identifies all files created during the engagement by timestamp range, (2) shreds each file with appropriate passes, (3) removes log entries matching engagement IP addresses and usernames, (4) restores file timestamps using the pre-operation baseline, and (5) runs bulk_extractor against a disk image snapshot to verify no recoverable artifacts remain. Use tcplay in scripted mode to create and mount encrypted volumes without interactive prompts, enabling automated secure storage during engagements.

## Legal and Ethical Considerations

Anti-forensic techniques must only be used within authorized penetration testing engagements with explicit written permission. Destroying evidence on systems you do not own or without authorization is a criminal offense in most jurisdictions (e.g., 18 U.S.C. 1519 in the United States, Computer Misuse Act Section 3 in the UK). Even within authorized engagements, document all anti-forensic actions thoroughly so the client understands what was cleaned and what forensic artifacts may remain for their incident response team.

## Integration with Other Tools

Anti-forensics connects directly to the digital-forensics skill domain. Every anti-forensic technique has a corresponding forensic detection method, and understanding both sides makes each more effective. The steganography skill provides additional steganographic tools beyond steghide (zsteg, stegcracker, stegseek). Post-exploitation techniques often require anti-forensic cleanup to maintain persistence without detection. Binary reverse engineering helps analyze anti-forensic tools themselves to understand exactly what artifacts they leave behind.

## Learning Resources

**This skill's supplementary files**: `payloads.md`, `test-cases.md`, `guides/filesystem-anti-forensics.md`, `guides/log-tamper-timestamp.md`, `guides/crypto-hide-data-destruction.md`

**Related skills**:
- `skills/digital-forensics/SKILL.md` - The defensive counterpart covering forensic analysis that detects anti-forensic techniques
- `skills/steganography/SKILL.md` - Additional steganographic tools and detection methods
- `skills/post-exploitation/SKILL.md` - Persistence mechanisms that must be cleaned up using anti-forensic techniques

**External resources**:
- [Anti-Forensics Techniques - HackTricks](https://book.hacktricks.xyz/forensics/basic-forensic-methodology/anti-forensic-techniques)
- [shred(1) Manual Page](https://man7.org/linux/man-pages/man1/shred.1.html)
- [tcplay GitHub](https://github.com/bwalex/tc-play)
- [NIST SP 800-88 Rev. 1](https://csrc.nist.gov/publications/detail/sp/800-88/rev-1/final) - Guidelines for Media Sanitization
- [SANS Anti-Forensics](https://www.sans.org/white-papers/anti-forensics/) - SANS Institute research on anti-forensic techniques and detection
