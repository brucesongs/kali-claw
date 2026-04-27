# Skill: Digital Forensics

> **Supplementary Files**:
> - `payloads.md` — Forensics command reference covering disk imaging, filesystem analysis, memory forensics, network forensics, log analysis, timeline reconstruction, file carving, anti-forensics detection, Windows/Linux forensics, and more
> - `test-cases.md` — Structured test case list covering evidence acquisition, filesystem analysis, memory forensics, network forensics, and anti-forensics detection

## Description

Digital forensics covers the complete workflow of disk forensics, memory forensics, network forensics, file recovery/carving, and chain of custody. The core objective is to extract, analyze, and present admissible electronic evidence from digital media while maintaining evidence integrity and legal validity.

The agent has mastered the SleuthKit command-line toolset (mmls, fsstat, fls, icat, ifind, ils), Autopsy forensics platform, Scalpel/Foremost file carving, Bulk Extractor high-performance extraction, ExifTool metadata analysis, PhotoRec data recovery, TestDisk partition repair, and has Volatility memory analysis and Wireshark/tshark network forensics capabilities.

## Use Cases

1. **Incident Response Forensics** - After a security incident, perform disk image analysis and memory dump extraction on compromised systems to reconstruct the attack timeline and lateral movement paths
2. **File Recovery and Carving** - Recover deleted files from damaged or formatted disks, reconstruct fragmented data using file header/tail signatures
3. **Malware Forensics** - Extract malicious processes, injected code, and rootkit-hidden modules from memory dumps, combined with disk analysis to locate persistence mechanisms
4. **Network Attack Reconstruction** - Reconstruct network attack traffic through PCAP analysis, identify C2 communications, data exfiltration, and lateral movement behavior
5. **Legal Electronic Evidence** - Strictly follow chain of custody procedures, generate court-admissible forensics reports and hash verification records

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **autopsy** | Web-based forensics platform built on SleuthKit | `autopsy -p 8080 -d /case/evidence` |
| **sleuth kit** | Command-line filesystem forensics toolset | `mmls image.dd && fls -r -o 2048 image.dd` |
| **volatility** | Memory dump analysis framework | `vol.py -f memory.dmp --profile=Win10 pslist` |
| **wireshark/tshark** | Network traffic analysis and PCAP forensics | `tshark -r capture.pcap -Y "http.request" -T fields -e http.host` |
| **binwalk** | Firmware/binary signature identification and extraction | `binwalk -Me firmware.bin` |
| **foremost** | Signature-based data carving | `foremost -t jpg,png,pdf -i image.dd -o /recovery` |

## Methodology

### Attack Chain

```
Evidence Collection    Disk Analysis        Memory Analysis      Network Reconstruction
(Imaging/Hash/         (Partition/          (Process/Injection/  (PCAP/C2/Data
 Write-Blocking)        Filesystem/Deleted)  Rootkit)             Exfiltration)
       |                    |                     |                      |
       v                    v                     v                      v
                Timeline Building        Report & Presentation
                (MAC Times/Event         (Chain of Custody/
                 Correlation)             Admissible Report)
```

**Phase Details**:

1. **Evidence Collection** - Use hardware write-blockers to prevent tampering, create bit-by-bit images of original media (dd / dcfldd / FTK Imager), calculate MD5/SHA256 hash verification values, and complete chain of custody forms
2. **Disk Analysis** - Use mmls for partition table analysis, fsstat for filesystem examination, fls for file/directory listing, and icat for file content extraction, focusing on searching for deleted files, hidden partitions, and slack space
3. **Memory Analysis** - Use Volatility to extract running processes (pslist/pstree), network connections (netscan), DLL injections (malfind), and registry hives (hivelist), identifying malicious code residency and rootkit hiding
4. **Network Reconstruction** - Use tshark to filter and analyze network traffic, reconstruct DNS queries, HTTP requests, TLS handshake metadata, and identify C2 communication patterns and data exfiltration behavior
5. **Timeline Building** - Combine disk MAC times (fls -m), network traffic timestamps, and memory process creation times; use log2timeline/supertimeline to generate a unified event timeline

### Defense Perspective

| Best Practice | Description | Priority |
|---------------|-------------|----------|
| **Write-Blockers** | Hardware write-blockers prevent any writes to original evidence, ensuring image integrity | CRITICAL |
| **Hash Verification** | Calculate MD5/SHA256 for original media and copies to verify images are identical to originals | CRITICAL |
| **Chain of Custody** | Completely record every handler, time, location, and operation from evidence collection to court presentation | CRITICAL |
| **Imaging Best Practices** | Use dd/dcfldd/FTK Imager to create bit-by-bit images; perform all analysis on copies | HIGH |
| **Documentation** | Detailed recording of every analysis step, tool versions, command parameters, and output results | HIGH |
| **Tool Validation** | Verify the accuracy of forensics tool output using known samples for cross-validation | MEDIUM |

## Practical Steps

### Step 1: Disk Image Analysis and Autopsy

Create bit-by-bit images and verify hashes, use SleuthKit command-line tools for quick analysis of partition tables, filesystems, and deleted files, or perform interactive forensics analysis through the Autopsy web platform.

### Step 2: Memory Dump Analysis with Volatility

Identify the memory dump's operating system profile, extract process lists and process trees, detect hidden processes, code injection, and API hooks, analyze network connections, and export suspicious processes with their loaded DLLs.

### Step 3: File Carving and Binwalk

Use foremost/scalpel for file signature-based deleted file recovery, use binwalk for recursive extraction of firmware and embedded files, use bulk_extractor for high-performance feature data extraction, and use exiftool for file metadata analysis.

### Step 4: Network Forensics and tshark

Perform traffic statistics and conversation analysis on PCAP files, reconstruct HTTP requests and DNS queries, extract transferred files, analyze TLS handshake metadata to identify C2 communications, and detect data exfiltration techniques such as DNS tunneling.

### Step 5: Timeline Reconstruction

Use SleuthKit to generate MAC timelines, combining disk MAC times, network traffic timestamps, memory process creation times, and system logs to build a unified event timeline that reconstructs the complete attack process.

> **Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.**

## Hacker Laws

1. **First Principles** - The foundation of digital forensics is data immutability and verifiability. Every conclusion must be traceable to original evidence bits, and every operational step must be reproducibly verifiable. Understanding filesystem structures, memory management mechanisms, and network protocol specifications is a prerequisite for accurate analysis.

2. **Trust but Verify** - Never assume tool output is 100% accurate. Cross-validate SleuthKit and Autopsy results, and use multiple methods to confirm critical findings. Verify file signatures and hashes after recovering deleted files; corroborate memory analysis results with network traffic timestamps.

3. **Murphy's Security Law** - In forensic analysis, the most critical evidence often appears in the least expected places: residual data in slack space, plaintext keys in swap partitions, and forgotten auto-start entries in the registry. Comprehensive coverage is more important than selective depth.

## Learning Resources

**This skill's supplementary files**: `payloads.md`, `test-cases.md`

**Related skills**:
- `skills/binary-reverse/SKILL.md` - Malware reverse engineering to complement forensic sample findings
- `skills/post-exploitation/SKILL.md` - Understanding attacker persistence mechanisms to guide forensic investigation direction

**Internal resources (this workspace)**:
- `memory/2026-03-21-digital-forensics-tools.md` - Complete digital forensics tool learning notes (SleuthKit/Autopsy/Scalpel/Bulk Extractor/ExifTool/PhotoRec/TestDisk)
- `security-tools-67/digital-forensics-cli-reference.md` - Forensics command-line tool reference

**External resources**:
- [SleuthKit Official Documentation](https://sleuthkit.org/sleuthkit/) - Complete reference for filesystem forensics toolset
- [Volatility 3 Documentation](https://volatility3.readthedocs.io/) - Memory forensics framework API and profile development
- [Autopsy Official Tutorial](https://sleuthkit.org/autopsy/) - Web forensics platform usage guide
- [Wireshark Wiki](https://gitlab.com/wireshark/wireshark/-/wikis/home) - Network protocol analysis reference
- [NIST SP 800-86](https://csrc.nist.gov/publications/detail/sp/800-86/final) - Guide to Integrating Forensic Techniques into Incident Response
- [HackTricks - Forensics](https://book.hacktricks.xyz/forensics/basic-forensic-methodology)
