# Reverse Engineering Advanced — Real-World Incident Case Studies

> 10 detailed case studies applying advanced RE techniques to real-world APT-grade malware, firmware, and obfuscated samples. Each case includes background, RE approach, key findings, IOCs, MITRE ATT&CK mapping, and lessons learned. Use as reference for engagement scoping and technique validation.

## Case Study 1 — Stuxnet (2010) — ICS-targeting multi-stage malware

### Background

Stuxnet is the first publicly known cyberweapon targeting industrial control systems (ICS). Discovered in 2010 but active since at least 2009, it targeted Iran's Natanz uranium enrichment facility. The malware used 4 zero-day Windows exploits and manipulated Siemens S7-300 / S7-400 PLCs to overspin centrifuges.

### RE Approach

1. **Sample acquisition**: Stuxnet sample from VirusBay / academic researchers
2. **Triage**: PE32+ DLL with multiple exported functions; section entropy normal; size ~500KB
3. **Static analysis**: Imports `WinCC.dll`, `s7otbxsx.dll`; large encrypted resource section
4. **Decompilation**: IDA Pro + Hex-Rays; identified PLC attack code in export functions
5. **Crypto identification**: FindCrypt detected RC4 + custom XOR; RC5 in C2 protocol
6. **Resource extraction**: Encrypted PLC blocks (DB 8080 / DB 8081) extracted via custom Python
7. **PLC block analysis**: Ghidra PowerPC plugin for S7 PLC bytecode; identified frequency modification routine

### Key Findings

- **4 zero-day exploits**: LNK vulnerability (CVE-2010-2568), print spooler (CVE-2010-2729), Win32k (CVE-2010-2743), task scheduler (CVE-2010-3338)
- **PLC attack**: Modified blocks 8080/8081 sent cascade pressure pulses to centrifuges at 1410 Hz (resonant frequency)
- **Steganography**: C2 traffic hidden in ICMP and HTTP requests to legitimate-looking servers (myspace.com, twitter.com)
- **Code quality**: Professional, modular, well-commented internal code
- **Targeting**: fingerprinted host environment to only activate on specific Siemens configurations

### IOCs

- **Mutex**: `FNKADLFNOIUSNKAJDSLFNASFKLAJSDLFKNAJSDFI`
- **Files**: `wtr4141.tmp`, `wtr4132.tmp`, `~WTR4141.tmp`
- **Registry**: `HKLM\SYSTEM\CurrentControlSet\Services\MsNetDrv`
- **C2 domains**: `todaymypc.com`, `bestfreesoft.ru`

### MITRE ATT&CK Mapping

- T1190 — Exploit Public-Facing Application
- T1203 — Exploitation for Client Execution
- T0853 — Exploitation for Privilege Escalation (ICS)
- T0859 — Valid Accounts (ICS)
- T0886 — Remote Services (ICS)
- T0858 — Change Operating Mode (ICS)

### Lessons Learned

1. **Multi-stage RE**: Stuxnet required 4 distinct RE workflows (Windows, kernel driver, PLC bytecode, steganography)
2. **ICS-specific tooling needed**: Standard PE tools cannot analyze PLC blocks; required Ghidra + custom PowerPC scripts
3. **Collaborative analysis**: Symantec's W32.Stuxnet Dossier was built from analysis across multiple researchers over months

## Case Study 2 — Pegasus FORCEDENTRY (2021) — iMessage 0-click

### Background

FORCEDENTRY (CVE-2021-30860) is the exploit used by NSO Group's Pegasus to deliver 0-click iMessage attacks. Discovered by Citizen Lab in 2021 targeting Bahraini activists. The exploit chain used a malformed PDF → GIF → JBIG2 → IMS exploit flow to escape iMessage sandbox and gain kernel R/W primitives.

### RE Approach

1. **Sample**: `.gif` attachment from forensic backup of targeted iPhone
2. **Format analysis**: File was a PDF disguised as GIF (header manipulation)
3. **PDF analysis**: Inside PDF was an XObject stream containing JBIG2-encoded image
4. **JBIG2 parsing**: JBIG2 segment structure abused to manipulate stack
5. **Exploit primitive reconstruction**: Stack layout, ROP chain, sandbox escape all documented
6. **Kernel stage**: Reverse kernel patch via `__mac_syscall` abuse

### Key Findings

- **JBIG2 stack manipulation**: JBIG2's segment-based architecture allows arbitrary stack operations
- **6-stage exploit**: PDF → GIF → JBIG2 → IMS → kernel → implant
- **Sandbox escape**: Used `task_set_exception_ports` Mach API
- **Kernel R/W primitive**: Patched `task->itk_space->is_table` for arbitrary read/write
- **Persistence**: Via `/private/var/jb/` (jailbreak-style) for some variants

### IOCs

- **Attachment hash**: `SHA256(b29b54b4... )` (varies per delivery)
- **Mach exception ports**: Anomalous `EXC_MASK_BAD_ACCESS` registration
- **Files**: `/private/var/mobile/Library/SMS/Attachments/`

### MITRE ATT&CK Mapping

- T1190 — Exploit Public-Facing Application
- T1203 — Exploitation for Client Execution
- T1548.001 — Setuid and Setgid
- T1067 — Bootkit
- T1542.001 — Boot or Logon Autostart Execution

### Lessons Learned

1. **File format deep dive required**: Standard AV scanners missed the exploit because PDF parser quirks were essential
2. **0-click exploit chains are complex**: 6 distinct stages, each requiring specialized RE
3. **Citizen Lab methodology**: Forensic backup → differential analysis → targeted RE
4. **JBIG2 is a powerful attack surface**: Underused format with complex segment model

## Case Study 3 — Equation Group REGIN (2014) — Multi-stage platform

### Background

REGIN is a sophisticated multi-stage spying platform attributed to the Equation Group (NSA-TAO). Discovered by Kaspersky in 2014 but active since at least 2008. Targeted telecoms, governments, and researchers. Platform uses staged loading with each stage encrypted and embedded in non-standard locations (registry, file slack, ICMP packets).

### RE Approach

1. **Sample**: Multiple stage 1 droppers from Kaspersky archive
2. **Triage**: Stage 1 is small (~20KB), uses RC4 with embedded key
3. **Stage 1 analysis**: Decrypts stage 2 from registry / ICMP / file slack
4. **Stage 2 analysis**: Deploys modules for specific targets (SQL, SMB, IOCs collection)
5. **Variant analysis**: BinDiff across 50+ variants to identify platform evolution
6. **Attribution**: Code style, IOCs, target list all match Equation Group TTPs

### Key Findings

- **5 stages**: Stage 1 (loader) → Stage 2 (orchestrator) → Stage 3 (extensions) → Stage 4 (modules) → Stage 5 (payloads)
- **Storage mechanisms**: File slack space, registry, ICMP packets, SMB named pipes
- **Targets**: GSM base stations, telecom backbone, governments, financial institutions
- **Persistence**: Multiple mechanisms including modified disk firmware (rare capability)
- **Encryption**: Custom + standard (RC4, AES) with per-target keys

### IOCs

- **Mutex**: `5F31F0A1-298F-4CFB-9AD6-8DADA36CFAB9`
- **Registry**: `HKLM\SOFTWARE\Microsoft\Cryptography\RNG\Seed` (non-standard use)
- **Files**: `/system32\config\<random>` (encrypted stage)
- **Network**: ICMP packets with payload in unused fields

### MITRE ATT&CK Mapping

- T1106 — Native API
- T1059.001 — PowerShell
- T1547.001 — Registry Run Keys
- T1219 — Remote Access Software
- T1573 — Encrypted Channel

### Lessons Learned

1. **Multi-stage RE requires patience**: Each stage has its own obfuscation, taking days to fully analyze
2. **Storage mechanisms matter**: Disk firmware modification is rare — its presence indicates top-tier actor
3. **BinDiff is essential for variants**: Clustered analysis revealed 5-year evolution of the platform
4. **Look beyond PE/ELF**: Regin hid stages in unexpected locations (ICMP, slack space)

## Case Study 4 — OLLVM-Protected Crackme (CTF) — Modern deobfuscation workflow

### Background

A senior-level crackme protected with OLLVM (Control Flow Flattening, Bogus Control Flow, Instruction Substitution) plus custom packing. Goal: recover 16-byte flag for CTF challenge.

### RE Approach

1. **Triage**: ELF64, statically linked, UPX-packed outer layer
2. **UPX unpack**: `upx -d` recovers inner OLLVM-protected binary
3. **CFF deobfuscation**: Identify dispatcher (large switch on EAX); run `deflat.py` with dispatcher 0x401800
4. **BCF removal**: Run `d810` IDA plugin for opaque predicate identification
5. **SUB simplification**: Custom miasm rules for ARX simplification
6. **Symbolic execution**: angr to find flag satisfying all constraints
7. **SMT key recovery**: Z3 encodes constraints from key check function

### Key Findings

- **3 obfuscation layers**: CFF + BCF + SUB all combined
- **Per-function state variable**: Each flattened function used different state register
- **Custom opaque predicates**: Not textbook OLLVM — required semantic analysis
- **Solution**: `flag{0bfu5c4t10n_d3f34t3d_w1th_sym_3x3c}`

### IOCs

- N/A (educational sample)

### MITRE ATT&CK Mapping

- T1027 — Obfuscated Files or Information
- T1027.002 — Binary Padding
- T1140 — Deobfuscate/Decode Mac Frameworks

### Lessons Learned

1. **OLLVM is defeatable**: Combining deflat + d810 + miasm handles most OLLVM variants
2. **Symbolic execution as fallback**: When decompile is messy, angr can solve constraints directly
3. **Document dispatcher address**: Each function may have its own — don't assume one dispatcher for all

## Case Study 5 — Apple iMessage FORCEDENTRY Recovery — Forensic workflow

### Background

This case explores forensic RE workflow used by Citizen Lab to recover FORCEDENTRY exploit from a victim's iPhone backup. Differs from Case 2 (which covered exploit mechanism) — focuses on forensic recovery methodology.

### RE Approach

1. **Backup acquisition**: iTunes-style encrypted backup from victim's Mac
2. **Backup decryption**: Brute force backup password via `hashcat -m 18400`
3. **Differential analysis**: Compare backup to known-clean iOS backup
4. **SMS attachments**: Located `.gif` in `/private/var/mobile/Library/SMS/Attachments/`
5. **File carving**: Use `bulk_extractor` to find deleted files
6. **Cross-reference**: Look for known NSO Group IOCs in attachment metadata

### Key Findings

- **Backup timestamp**: Showed attachment received 24h before reported infection date
- **Sender**: +44 number (UK burner), now deactivated
- **File carving**: Recovered partial JBIG2 stream from SQLite WAL

### IOCs

- **Attachment hash**: `b29b54b4...`
- **Sender**: +44 7700 900XXX (redacted)
- **Receive timestamp**: 2021-02-10 14:32 UTC

### MITRE ATT&CK Mapping

- T1213.002 — Data from Information Repositories (Backup)
- T1106 — Native API
- T1212 — Exploitation for Credential Access

### Lessons Learned

1. **Backup RE is underused**: iTunes backups preserve artifacts that get cleaned from device
2. **File carving**: SQLite WAL files can hold weeks of deleted data
3. **Cross-reference with public IOCs**: Citizen Lab maintains public NSO Group indicator database

## Case Study 6 — Cisco Router Firmware — Network device RE

### Background

A customer engagement required security assessment of Cisco IOS-XE firmware for a router fleet. Goal: identify potential privilege escalation paths in custom CLI parser.

### RE Approach

1. **Firmware acquisition**: `.bin` image downloaded from customer support portal
2. **Binwalk scan**: Identified ZIP header, ELF, and CRC tables
3. **Extraction**: `binwalk -e` extracted IOS loader; CRC verification
4. **ELF analysis**: Ghidra PowerPC plugin for IOS main binary (`linux_iosd-image`)
5. **CLI parser reverse**: Identified `parser_register_command` calls; mapped command tree
6. **Vulnerability hunting**: Looked for `strcpy` / `sprintf` usage in CLI handlers
7. **Dynamic validation**: Tested candidates on physical test router in lab

### Key Findings

- **Big-endian PowerPC**: Required Ghidra language configuration
- **CLI parser structure**: Trie-based, with per-mode handlers
- **Vulnerability found**: Stack overflow in `show interfaces <X>` command when X is long (>1024 chars)
- **Trigger**: Authenticated user with `show` privilege can crash router (DoS) — escalation to RCE requires further primitives
- **Disclosure**: Reported to Cisco PSIRT; fixed in 2024-Q3 advisory

### IOCs

- N/A (legitimate research)

### MITRE ATT&CK Mapping

- T1068 — Exploitation for Privilege Escalation
- T1200 — Hardware Additions
- T0890 — Exploitation for Privilege Escalation (ICS)

### Lessons Learned

1. **IOS is not Linux**: PowerPC, custom scheduler, no ASLR
2. **CLI parser is main attack surface**: Tons of legacy C code with weak input handling
3. **Big-endian tripping hazard**: x86-centric RE assumptions break on Cisco hardware

## Case Study 7 — Mirai ELF Bot Variants — MIPS variant analysis

### Background

After Mirai source code release in 2016, hundreds of variants emerged. A customer wanted analysis of a specific variant family targeting their IoT devices.

### RE Approach

1. **Sample collection**: 200+ ELF MIPS samples from honeypot over 6 months
2. **Triage**: All statically linked MIPS ELF; sizes 50-200KB
3. **Decompilation**: Ghidra MIPS plugin; main() pattern consistent
4. **String deobfuscation**: XOR with per-sample single-byte key
5. **Variant analysis**: Kam1n0 to cluster by assembly similarity
6. **Protocol reverse**: Identified C2 protocol — TCP/23 or TCP/48101, custom binary format
7. **Family attribution**: Clustered 200 samples into 7 variant families

### Key Findings

- **Common ancestor**: All variants shared ~80% code with original Mirai
- **Differentiation**: C2 protocol, encryption, propagation strategy
- **Obfuscation evolution**: Newer variants added UPX + custom XOR layer
- **Targets**: Original targeted telnet → newer variants targeted TR-064 (router management)

### IOCs

- **C2 server**: Port 23 or 48101
- **Credentials list**: 60+ default IoT passwords (`admin/admin`, `root/xc3511`, etc.)
- **Mutex**: Per-variant — `mirai_cpp`, `mirai_go`, etc.

### MITRE ATT&CK Mapping

- T1190 — Exploit Public-Facing Application
- T1110 — Brute Force
- T1059.004 — Unix Shell
- T1105 — Ingress Tool Transfer
- T1498 — Network Denial of Service

### Lessons Learned

1. **Kam1n0 scales variant analysis**: 200 samples clustered in 4 hours vs. weeks of manual work
2. **MIPS RE workflow**: Ghidra works well; IDA Pro MIPS plugin less polished
3. **String deobfuscation automation**: Built Python tool to brute force XOR keys at scale
4. **Family attribution requires manual review**: Kam1n0 clusters, human confirms

## Case Study 8 — BlackCat/ALPHV (2023) — Rust ransomware analysis

### Background

BlackCat (ALPHV) is one of the first major Rust-based ransomware families. RaaS (Ransomware-as-a-Service) operation targeting Windows + Linux environments. Notable for: Rust language, multi-platform, sophisticated affiliate program.

### RE Approach

1. **Sample**: Windows PE64 + Linux ELF variants
2. **Triage**: Rust-compiled, statically linked; ~600KB
3. **String deobfuscation**: Rust strings have length prefix; standard `strings` misses many
4. **Demangling**: Rust name mangling — used `rustfilt` for demangling
5. **Encryption routine**: Identified ChaCha20 + Curve25519 hybrid scheme
6. **Configuration extraction**: Embedded JSON config (RSA-encrypted) decoded via extracted private key
7. **Affinity check**: Bypasses Russian / Ukrainian / Belarusian hosts via GetSystemDefaultLCID
8. **Anti-recovery**: VSS delete via `vssadmin delete shadows`

### Key Findings

- **Rust obfuscation challenges**: Heavy name mangling, verbose error handling, generics monomorphization
- **Encryption scheme**: Curve25519 (key exchange) + ChaCha20-Poly1305 (file encryption) — strong, not crackable
- **Affiliate-friendly**: Configurable target lists, exclusion rules
- **Multi-platform**: Single Rust codebase compiles to Windows + Linux
- **Initial access**: Affiliates primarily use PSAs (Purchase of System Access) from initial access brokers

### IOCs

- **Mutex**: `BlackCat_<random>`
- **Files**: `*.<random5>`, `README-<random>.txt`
- **Registry**: `HKLM\SOFTWARE\BlackCat`
- **Network**: Tor onion for leak site (varies)

### MITRE ATT&CK Mapping

- T1486 — Data Encrypted for Impact
- T1490 — Inhibit System Recovery
- T1087 — Account Discovery
- T1003 — OS Credential Dumping
- T1071.001 — Web Protocols (C2)

### Lessons Learned

1. **Rust RE workflow**: Requires different tooling (`rustfilt`, custom demanglers)
2. **Modern crypto is unbreakable**: Recovery must rely on affiliate errors, not crypto flaws
3. **Cross-language samples**: PE and ELF variants share code — analyze once, port findings

## Case Study 9 — Cobalt Strike Beacon Analysis

### Background

Cobalt Strike beacons are ubiquitous in red team engagements and real intrusions. A SOC team needed to extract configs from captured beacons for IOC dissemination.

### RE Approach

1. **Sample acquisition**: Beacon binaries from EDR quarantine
2. **Triage**: PE32+ DLL or shellcode blob; size varies 100KB-300KB
3. **Stager analysis**: For stager variants, reverse stage 1 to find stage 2 URL
4. **Config location**: Beacon has embedded config block at fixed offset (varies by version)
5. **Config extraction**: Used `1768.py` (Didier Stevens) — decodes settings 0-56
6. **Decryption**: XOR with key derived from beacon metadata field
7. **Documentation**: Per-beacon report with C2 server, port, watermark, kill date

### Key Findings

- **Config settings of interest**:
  - Setting 1: AES key (decryption)
  - Setting 5: C2 server
  - Setting 6: Port
  - Setting 45: Watermark (threat actor group ID)
  - Setting 31: Process injection target
  - Setting 37: User agent
- **Variants**: Public leaks (leaked 4.9 source) and modified forks (BRC4, Brute Ratel)
- **Evasion techniques**: Sleep obfuscation (Ekko), syscalls, sleep mask

### IOCs

- **Per beacon**: SHA256, C2 server, watermark
- **Common**: Setting 45 watermark "57" = retail customer, "0" = trial / leaked

### MITRE ATT&CK Mapping

- T1071.001 — Web Protocols
- T1573 — Encrypted Channel (HTTPS, DNS)
- T1059 — Command and Scripting
- T1105 — Ingress Tool Transfer
- T1218.010 — Regsvr32 (Application Bypass)

### Lessons Learned

1. **Beacon config extraction is high-value**: SOC team uses watermark to track actors
2. **Modified forks are common**: Custom beacons may have non-standard offsets — adapt parser
3. **Sleep mask obfuscation**: Modern beacons encrypt themselves in memory during sleep

## Case Study 10 — APT41 DNS Tunneling Binary — Protocol reverse

### Background

APT41 (Chinese state-sponsored) uses DNS tunneling for stealthy C2. A sample was recovered from an incident response engagement; protocol reverse needed to decode captured traffic.

### RE Approach

1. **Sample**: PE32+ sample from IR triage
2. **Static analysis**: Imports `DnsQuery_A`, `WSAStartup`; main loop builds DNS queries
3. **Decompilation**: Hex-Rays decompile of query construction function
4. **Protocol identification**:
   - **Domain generation**: DGA seeded with current date + secret key
   - **Encoding**: Base32 of payload bytes
   - **Chunking**: Max 63 chars per label, max 3 labels per query
   - **Direction**: TX (beacon) = `*.d.<dga>`, RX (commands) = TXT records
5. **PCAP decode**: Applied protocol to 5000+ captured DNS queries; decoded 47 commands
6. **Command structure**: 2-byte opcode + variable payload (length-prefixed)

### Key Findings

- **Stealthy protocol**: Queries looked like benign CDNs (similar length, frequency)
- **DGA detection**: Daily seed produced 1000 candidate domains
- **TXT record abuse**: Commands delivered via TXT records, encoded as base64
- **Encryption**: Custom XOR with per-command key
- **Persistence**: Registry Run key + scheduled task

### IOCs

- **Mutex**: `WininetStartup`
- **Files**: `%APPDATA%\Microsoft\Network\<random>.exe`
- **Registry**: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsDefender`
- **Network**: DGA-generated subdomains of legitimate-looking domains

### MITRE ATT&CK Mapping

- T1071.004 — DNS
- T1573 — Encrypted Channel
- T1105 — Ingress Tool Transfer
- T1053.005 — Scheduled Task
- T1547.001 — Registry Run Keys

### Lessons Learned

1. **Protocol RE workflow**: Static analysis → PCAP correlation → encoder/decoder Python script
2. **DNS tunneling is common in APTs**: Worth checking in IR engagements with anomalous DNS volume
3. **DGA identification helps**: Once seed formula known, predictive domain blocking possible
4. **Cross-discipline work**: DNS protocol RE requires both malware analyst + network analyst skills

---

## Cross-Case Themes

### Theme 1 — Multi-stage RE requires patience

Stuxnet, Regin, FORCEDENTRY all required multi-stage workflows. Each stage has its own obfuscation and skill requirements (Windows, kernel, PLC, JBIG2). Plan time accordingly — 5-7 days for APT-grade multi-stage samples.

### Theme 2 — Modern tooling is essential

- angr / KLEE for symbolic execution
- BinDiff / Diaphora / Kam1n0 for variant analysis
- binwalk / FACT / EMBA for firmware
- deflat / d810 / miasm for OLLVM
- Z3 for SMT-assisted key recovery

### Theme 3 — Cross-discipline RE

Modern APT samples span multiple domains: Windows PE, kernel drivers, network protocols, file formats (PDF, JBIG2), smart contracts, PLC bytecode. Specialists must collaborate.

### Theme 4 — Attribution requires multiple signals

Attribution in REGIN, Pegasus, Stuxnet relied on:
- Code style (variable naming, idioms)
- Target list (who was attacked)
- Build infrastructure (compiler versions, build paths)
- Operational patterns (C2 infrastructure, mutex naming)

### Theme 5 — Disclosure is part of the job

Cisco router finding, Cobalt Strike IOC dissemination, vendor notification for Regin — all required responsible disclosure. Document findings clearly for downstream consumer.

---

## Engagement Workflow Summary

For each real-world case, the workflow follows:

1. **Scoping**: Understand objectives, time budget, deliverables
2. **Triage**: File type, hash, packer identification
3. **Static analysis**: Imports, strings, sections, entropy
4. **Unpacking / deobfuscation**: UPX, VMProtect, OLLVM
5. **Symbolic execution** (if applicable): angr / KLEE / manticore
6. **Decompilation**: IDA Pro / Ghidra / Binary Ninja
7. **Variant analysis** (if applicable): BinDiff / Diaphora / Kam1n0
8. **Firmware extraction** (if firmware): binwalk / FACT / EMBA
9. **Crypto identification**: FindCrypt, manual analysis
10. **Reporting**: Findings, IOCs, MITRE ATT&CK mapping, YARA rules

---

## References

- MITRE ATT&CK — https://attack.mitre.org/
- "Stuxnet Dossier" (Symantec, 2011) — https://www.wired.com/2011/07/ff_stuxnet/
- "FORCEDENTRY" (Citizen Lab, 2021) — https://citizenlab.ca/2021/09/forcentry-nso-group-imero-zero-click-exploit-captured/
- "Equation Group" (Kaspersky, 2015) — https://securelist.com/equation-the-death-star-of-malware-war/69269/
- "REGIN" (Symantec, 2014) — https://www.symantec.com/connect/blogs/regin-top-tier-espionage-tool-allows-discrete-collection
- "Pegasus" (Citizen Lab, 2016, 2021, 2024) — https://citizenlab.ca/tag/pegasus/
- "APT41" (Mandiant, 2019-2024) — https://www.mandiant.com/resources/apt41
- "BlackCat / ALPHV" (Cisco Talos, 2023) — https://blog.talosintelligence.com/blackcat-ransomware/
- "Mirai" (MalwareMustDie, 2016) — https://github.com/MalwareMUSTDie/MalwareMustDie
- "Cobalt Strike Config Parser" (Didier Stevens) — https://didierstevens.com/files/research/1768.py.txt
- angr documentation — https://docs.angr.io/
- Ghidra documentation — https://ghidra-sre.org/
- BinDiff — https://www.zynamics.com/bindiff.html
- EMBA — https://github.com/e-m-b-a/emba
- FACT — https://github.com/fkie-cad/FACT_core
