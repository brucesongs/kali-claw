# Mainframe Security Playbook

## Introduction

IBM mainframes still process the majority of the world's credit card transactions, social security records, stock trades, and airline reservations. Banks, insurers, and governments run z/OS in the core of their estate because the platform delivers transactional integrity and hardware-assisted isolation that no distributed system matches. The trade-off is a widening skills gap: the average mainframe operator is closer to retirement than to entry, and most red teams lack anyone who can credibly navigate TSO, read a RACF dump, or audit APF libraries. A pentester who can cross that gap adds value that very few peers can replicate. This playbook is the operational reference for closing that gap on authorized engagements. It covers z/OS architecture at the depth required to assess it, builds a free lab from Hercules and the TK4-/MVSCE community distributions, walks through the RACF methodology that produces high-quality findings, and closes with defense patterns the practitioner can recommend to system owners.

The playbook assumes the reader is comfortable with general enterprise pentest concepts (identity, access control, lateral movement) but is new to mainframe-specific primitives (TSO, JCL, RACF, APF). Where a concept exists in both worlds (e.g., RACF UACC vs. file permissions), the analog is called out explicitly. The goal is to take a competent Linux/Windows pentester and make them competent on z/OS within the scope of a single engagement.

## z/OS Architecture Refresher

### Hardware and Logical Partitioning

IBM Z hardware runs one or more Logical Partitions (LPARs) under the PR/SM (Processor Resource/System Manager) hypervisor. PR/SM is hardware-assisted (Type-1, certified at Common Criteria EAL5+), and isolation between LPARs is enforced by the processor complex itself. From an attacker's perspective, "mainframe == LPAR == z/OS instance" is the rule of thumb; cross-LPAR attacks are essentially out of scope for a typical engagement.

```text
// Layered view
IBM Z CEC (Central Electronic Complex)
  +-- PR/SM hypervisor (hardware)
       +-- LPAR 1: z/OS production (the engagement target)
       +-- LPAR 2: z/OS development
       +-- LPAR 3: Linux on Z (under z/VM or KVM on Z)
```

### Address Spaces

Inside a z/OS LPAR, work runs in address spaces. Each address space has its own virtual memory (up to 64 bits of address space) and is isolated from every other address space by the hardware. The relevant address spaces for an engagement are:

```text
MASTER   -- the master scheduler
RACF     -- the Resource Access Control Facility address space (security server)
JES2     -- the job entry subsystem (batch + spool)
TSO      -- the foreground region; each user gets a TSO address space at logon
CICS     -- one or more CICS regions (CICS is short for CICS Transaction Server)
DB2      -- DB2 database manager (MSTR, DBM1, IRLM, DIST address spaces)
IMS      -- IMS DB/DC region (if present)
VTAM     -- VTAM address space (SNA + TN3270 listener)
z/OSMF   -- z/OS Management Facility address space (REST)
OMVS     -- Unix System Services address space (z/OS Unix)
```

Understanding which subsystems are present at the engagement scope is the first reconnaissance step. A `D A,L` operator command lists active address spaces.

### TSO, ISPF, JES, CICS, VTAM, RACF Roles

```text
TSO/E    -- the interactive shell; users log on via VTAM/TN3270 to TSO
ISPF     -- the dialog manager layered on TSO; primary UI for most operators
JES2     -- schedules batch jobs and manages the spool; primary batch interface
CICS     -- OLTP subsystem; transactions are submitted by 3270 or web service
VTAM     -- provides SNA + TN3270; the network face of the mainframe
RACF     -- security server; authenticates users and authorizes resources
z/OSMF   -- REST API; the modernization path for many shops
```

### EBCDIC and Data Representation

z/OS stores character data in EBCDIC (Code Page 037, 1047, etc.), not ASCII. This is a perennial source of bugs in tooling that touches mainframe data. When transferring data between workstation and mainframe, ensure the transfer mode is set to text (so the byte-code conversion happens) or binary (so it does not, e.g., for IRRDBU00 unloads). In `c3270`, `ASCII` and `EBCDIC` commands toggle display mode; in `scp`/`ftp`, modes are `ascii` and `binary`.

### The Security Server: RACF vs ACF2 vs Top Secret

IBM z/OS supports three competing security servers:

```text
RACF      -- IBM Resource Access Control Facility (majority market share)
ACF2      -- Computer Associates (CA) ACF2 (common in large banks)
Top Secret -- Broadcom (CA) Top Secret (common in insurance, government)
```

This skill assumes RACF; ACF2 and Top Secret use different command vocabularies but the conceptual model (users, groups, resource classes, access lists) is similar. If the engagement target uses ACF2 or Top Secret, the methodology still applies but the command reference (Section 6 of `payloads.md`) must be translated.

## Building a Mainframe Lab

A free, reproducible lab is the foundation for the mainframe skill. The canonical stack is Hercules (open-source emulator) plus TK4- or MVSCE (free MVS 3.8j distributions).

### Option 1: Hercules + TK4- on Linux

TK4- is the most widely used free mainframe. It ships pre-configured with sample users, datasets, and tooling.

```bash
# Debian/Ubuntu prerequisites
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev flex bison \
  git autoconf automake libtool pkg-config zlib1g-dev

# Build SDL-Hercules-390 (Hyperion)
git clone --depth=1 https://github.com/SDL-Hercules-390/hyperion.git
cd hyperion
./util/bldcnf.pl
./configure --prefix=/opt/hercules
make -j"$(nproc)"
sudo make install

# Fetch TK4-
mkdir -p ~/mf-lab && cd ~/mf-lab
git clone --depth=1 https://github.com/MVS-SOW/tk4-.git
cd tk4-

# Read README for current default ports and credentials
less README.md

# Start TK4-
./mvs
# In another terminal, connect with c3270
c3270 localhost:3270
```

### Option 2: Hercules + MVSCE

MVSCE (Community Edition) is an alternative distribution with newer tooling and updated sample datasets.

```bash
mkdir -p ~/mf-lab && cd ~/mf-lab
git clone --depth=1 https://github.com/MVS-SOW/MVSCE.git
cd MVSCE
./mvs
```

### Option 3: zPDT for Licensed z/OS

For engagements that require the actual z/OS (rather than MVS 3.8j), IBM Z Personal Development Test (zPDT) is the licensed path. zPDT runs a real z/OS on x86 hardware under an emulator that IBM supports. Acquiring zPDT requires an IBM customer relationship and a license; it is out of scope for this skill's lab guidance but worth knowing about for client-side development.

### Option 4: Docker and Kubernetes Wrappers

Several community projects wrap Hercules + TK4- in a container for reproducibility. They are useful when you need a known-good lab environment to share with a teammate, or when you want a lab that survives a workstation rebuild.

```bash
# Pattern (verify the specific image before pulling)
docker run -d --name mf-lab -p 3270:3270 \
  -v "$HOME/mf-lab/tk4-":/tk4 REPLACE_WITH_YOUR_MF_IMAGE:latest

# Or build your own Dockerfile
cat > Dockerfile <<'EOF'
FROM debian:stable
RUN apt-get update && apt-get install -y \
    build-essential cmake libssl-dev flex bison git \
    autoconf automake libtool pkg-config zlib1g-dev c3270
WORKDIR /opt
RUN git clone --depth=1 https://github.com/SDL-Hercules-390/hyperion.git \
 && cd hyperion && ./util/bldcnf.pl && ./configure --prefix=/opt/hercules \
 && make -j"$(nproc)" && make install
WORKDIR /tk4
EXPOSE 3270
CMD ["/opt/hercules/bin/hercules", "-f", "hercules.cnf"]
EOF
```

### Verifying the Lab

After the lab is up, verify each layer.

```text
1. Hercules console shows MVS messages and a wait state ready for logons
2. c3270 connects and renders the VTAM logon panel
3. The default user (per README) authenticates and reaches TSO READY
4. ISPF launches (option ISPF from READY)
5. LISTUSER * returns sample users
6. JES2 is reachable via SDSF (ISPF option =M.5 or SDSNF at READY)
```

If any step fails, common causes are: a stale TK4- mirror, a Hercules build against an incompatible OpenSSL, port conflicts on 3270, or insufficient shared memory on the host. The Hercules and TK4- communities on GitHub Issues are responsive.

## RACF Methodology

The RACF methodology proceeds in five phases. Each phase produces artifacts that feed the next.

### Phase 1: User and Group Enumeration

Goal: produce a complete inventory of users, groups, and their attributes.

```ts
LISTUSER *                // every user; capture to a dataset
LISTGRP *                 // every group
SEARCH FILTER(*) CLIST(NAME)
```

Filter the output for SPECIAL, AUDITOR, and OPERATIONS attribute holders. These are the RACF equivalents of Domain Admins. Count revoked-but-not-deleted users and dormant accounts (PASSDATE older than policy).

### Phase 2: Dataset Profile Inventory

Goal: produce a dataset access matrix.

```ts
SEARCH CLASS(DATASET) FILTER(SYS1.**)
SEARCH CLASS(DATASET) FILTER(PROD.**)
SEARCH CLASS(DATASET) FILTER(PAYROLL.**)
LISTDSD DATASET('SYS1.PARMLIB') ALL
```

For each sensitive dataset, record UACC, audit setting, and the access list. Flag UACC > READ and broad-group UPDATE/ALTER.

### Phase 3: APF Library Audit

Goal: identify APF-authorized libraries backed by user-writable datasets.

```ts
SETR LIST                 // dump APF list
LISTDSD DATASET('SYS1.LINKLIB') ALL
LISTDSD DATASET('MYUSER.LINKLIB') ALL    // suspect entry
```

Cross-reference dynamic APF entries with `SYS1.PARMLIB(PROGxx)`. A writable APF dataset is the highest-severity finding on most engagements.

### Phase 4: General Resource Class Review

Goal: identify over-permissive general resource profiles.

```ts
SEARCH CLASS(FACILITY) FILTER(**)
SEARCH CLASS(TERMINAL) FILTER(**)
SEARCH CLASS(SURROGAT) FILTER(**)
SEARCH CLASS(STARTED) FILTER(**)
SEARCH CLASS(OPERCMDS) FILTER(**)
```

The SURROGAT class is particularly interesting: it lets one user submit jobs under another user ID. Broad SURROGAT profiles enable impersonation.

### Phase 5: Programmatic Verification

Goal: convert findings into demonstrable impact.

```bash
# SEAR API for programmatic verification
curl -k -u "$SEAR_USER:$SEAR_PASS" \
  "https://$SEAR_HOST/zosmf/api/rest/sear/datasets/MYUSER.LINKLIB" \
  | jq '.access'

# IRRDBU00 unload for offline analysis
# (See payloads.md Section 14 for JCL)
```

On client work, demonstrate READ access to a sensitive dataset (and document). Do not demonstrate privilege escalation without explicit authorization.

## Real-World Incidents

### Chase Manhattan Mainframe (2014)

The 2014 JP Morgan Chase breach affected roughly 83 million customer records. While the public reporting focused on the web-tier compromise, the incident underscored how a foothold in adjacent infrastructure can pivot toward mainframe-hosted account data. The lessons for mainframe assessments are:

```text
1. Treat the mainframe as a target reachable from the corporate network
2. Audit the credentials cached on adjacent servers that talk to the mainframe
3. Review RACF user IDs used by middleware (often over-privileged)
4. Examine job submission paths from middleware to the mainframe
```

### Financial Sector Internal Assessments

Most mainframe security incidents never become public; they surface during regulatory examinations or internal audits. Patterns that emerge from anonymized reports:

```text
- APF datasets with UACC=UPDATE due to a 1990s-era migration that was never cleaned up
- SPECIAL users created for a one-off task and forgotten
- RACF password rules left at default (8 chars, no mixed case) for decades
- TN3270 reachable from the corporate network without TLS
- z/OSMF REST API exposed to a broader IP range than intended
- IRRDBU00 unload files cached on workstations and never deleted
```

### DEF CON Mainframe Village

The DEF CON mainframe village is the primary public venue for mainframe security research. Key contributions:

```text
- mainframed/Enumeration scripts (open-source RACF/TSO discovery)
- Public Hercules + TK4-/MVSCE tutorials
- Research on APF and LINKLIST abuse
- Presentations on RACF internals
- Demonstrations of CICS transaction fuzzing
```

### Kaspersky Securelist RACF Deep Dives

Kaspersky's Securelist published two-part research on RACF that remains the single best public technical reference for an attacker's perspective. Search Securelist for "RACF" to find:

```text
- Part 1: "Approach to mainframe security" -- covers RACF data model, SMF, IRRDBU00
- Part 2: "Deconstructing RACF" -- covers command internals, audit evasion, defense
```

The articles include concrete commands and a level of detail rare in mainframe public literature. Practitioners should read both before any engagement.

## Defense Patterns

### Hardening RACF

```ts
// Password policy
SETROPTS PASSWORD(INTERVAL(30))         // rotation every 30 days
SETROPTS PASSWORD(RULES((ALPHANUM)))     // require mixed alphanumeric
SETROPTS PASSWORD(HISTORY(8))            // remember last 8
// Where supported: PASSWORD(MIXEDCASE) for case-sensitivity

// Audit posture
SETROPTS AUDIT                            // audit on
SETROPTS SAUDIT                           // audit SPECIAL use
SETROPTS CMDVIOL                          // audit command violations
SETROPTS OPERAUDIT                        // audit OPERATIONS use

// Clean up dormant accounts
//   1. REVIEW LISTUSER output monthly
//   2. REVOKE users inactive > 60 days
//   3. DELUSER revoked users after 30 days observation
//   4. Strip attributes from non-essential accounts
```

### APF and Linklist Hygiene

```text
- Run SETR LIST monthly; reconcile against gold source
- All APF datasets must be UACC=READ
- Restrict PROGxx changes to controlled change windows
- Enable IBM Health Checker APF_CHECK and remediate findings
- Treat any dynamic APF addition as a P1 change
```

### SMF and SIEM Integration

```text
- Capture SMF 30, 80, 81, 83, 14, 15, 110, 119
- Forward to SIEM via IBM Common Data Provider or equivalent
- Define alerts:
    * SMF 80 RACF command violations (return code indicating deny)
    * SMF 81 ADDUSER/ALTUSER/DELUSER outside change windows
    * SMF 80 SPECIAL attribute usage outside jump server IPs
    * SMF 14/15 reads of sensitive datasets from unexpected user IDs
    * SMF 80 TN3270 logon from non-corporate IP
```

### Encryption

```text
- Enable Coupling Facility (CF) encryption for shared DASD and CF structures
- Use z/OS Encryption Readiness Technology (zERT) to enforce TLS on TN3270 (port 992), FTP, and z/OSMF
- Use ICSF for cryptographic key management
- Enable dataset-level encryption for sensitive HLQs (z/OS V2R3+)
```

### Multi-Level Security

```text
- Where classification is required, enable RACF MLS (Multi-Level Security) mode
- Document SECLABEL ownership and review periodically
- MLS adds mandatory access control (MAC) on top of RACF's discretionary access control
- Mis-assigned SECLABEL defeats MLS; audit label ownership carefully
```

### z/OSMF Hardening

```text
- Restrict z/OSMF REST to jump-server IP ranges
- Require TLS 1.2+ with strong cipher suites
- Protect SEAR endpoints with FACILITY class profiles (IRRSEAR.**)
- Audit z/OSMF REST calls via SMF
- Review z/OSMF user IDs for over-privilege; prefer scoped roles
```

### Detection Use Cases

```text
1. Mass LISTUSER or SEARCH commands from a single user (SMF 81)
2. SETR LIST from non-SPECIAL users (SMF 81)
3. IRRDBU00 job submission (SMF 81, JES2)
4. APF dataset open for WRITE (SMF 14/15)
5. z/OSMF REST call from non-jump IP (z/OSMF SMF)
6. SEAR API call (SMF 80 against IRRSEAR.* profiles)
7. TN3270 logon from non-corporate IP (SMF 80, TERMINAL class)
8. CICS transaction with CMDPROT=NONE invoked externally (SMF 110)
```

## Operational Considerations

### Engagement Scoping

Before any mainframe engagement, agree on scope in writing:

```text
- Target LPAR(s) and hostname(s)
- Allowed subsystems (TSO, CICS, DB2, JES2, z/OSMF, SEAR)
- Allowed user IDs and privilege level
- Read-only vs. write demonstrations
- Whether APF and LINKLIST manipulation is in scope
- Production vs. development LPAR
- Whether IRRDBU00 unload is permitted
- Change-control and notification procedures
```

### Evidence Handling

```text
- Capture LISTUSER, LISTGRP, SETR LIST, LISTDSD output to datasets
- Download evidence via encrypted SFTP or z/OSMF REST
- Store evidence on an engagement-controlled workstation
- Delete IRRDBU00 unloads after engagement close-out
- Encrypt evidence at rest (LUKS, FileVault, BitLocker)
- Follow the client's data retention policy
```

### Reporting

```text
- Map each finding to MITRE ATT&CK for Enterprise
- Include the LISTDSD/PERMIT/LISTUSER snippet that demonstrates the finding
- Propose least-privilege remediation (ALTDSD/PERMIT/DELUSER)
- Quantify blast radius (number of affected datasets, users, transactions)
- Offer a follow-up assessment to verify remediation
```

## References

- Kaspersky Securelist: "Approach to mainframe security" (search Securelist for "RACF") -- the canonical public attacker-perspective reference
- Kaspersky Securelist: "Deconstructing RACF" -- the follow-up deep dive on RACF internals
- IBM Redbooks: "z/OS Security Server RACF Security Administrator's Guide" (current version at time of engagement)
- IBM Redbooks: "IBM Security zSecure Suite" -- reference for commercial audit tooling
- mainframed/Enumeration: https://github.com/mainframed/Enumeration -- open-source z/OS pentest scripts (TSO/ISPF/RACF/APF/datasets)
- Mainframe-Renewal-Project/SEAR: https://github.com/Mainframe-Renewal-Project/sear -- REST API for RACF
- SDL-Hercules-390/hyperion: https://github.com/SDL-Hercules-390/hyperion -- Hercules emulator source
- MVS-SOW/tk4-: https://github.com/MVS-SOW/tk4- -- TK4- MVS 3.8j distribution
- MVS-SOW/MVSCE: https://github.com/MVS-SOW/MVSCE -- MVSCE Community Edition
- ricardojba/Even-More-Awesome-Mainframe-Hacking -- curated resource list
- tr3x85/Mainframe_hacking -- consolidated mainframe hacking resources
- hacksomeheavymetal/zOS -- tooling and pentesting notes
- DEF CON mainframe village -- annual venue for public mainframe security research
- Open Mainframe Project -- Linux Foundation hub for open-source mainframe tooling
- IBM z/OSMF documentation: https://www.ibm.com/docs/en/zos/ -- z/OSMF REST API reference
- IBM Health Checker for z/OS: https://www.ibm.com/docs/en/zos/ -- native health-check framework
