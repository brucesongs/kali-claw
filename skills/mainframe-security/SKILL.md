---
name: mainframe-security
description: IBM z/OS, RACF (Resource Access Control Facility), CICS, DB2, JES2, TSO/ISPF penetration testing; APF library abuse, dataset access control, SNA/Appc attacks, and legacy mainframe security assessment for financial/government environments.
origin: github-trending-2026
version: "0.2.0.2"
compatibility:
  - claude-code
  - agent-sdk
  - openclaw
  - cursor
allowed-tools:
  - Bash
  - Read
  - Edit
  - Write
  - Glob
  - Grep
metadata:
  domain: mainframe
  category: mainframe
  tool_count: 13
  guide_count: 4
  mitre: "TA0006-Credential Access, T1078-Valid Accounts, T1003-OS Credential Dumping"
  keywords:
    - mainframe
    - zos
    - racf
    - cics
    - db2
    - jes2
    - tso
    - ispf
    - apf
    - sna
    - jcl
    - ibm-z
    - vtam
    - tk4
  last_reviewed: "2026-07-26"
---


# Skill: Mainframe Security (IBM z/OS / RACF)

> **Supplementary Files**:
> - `payloads.md` -- 18 sections covering mainframe ecosystem, Hercules lab setup, TN3270, TSO/ISPF, RACF commands, APF library audit, dataset access, JCL, CICS, DB2, SNA, JES2, IRRDBU00 unload, SEAR API, z/OSMF REST, SMF detection, and a quick reference cheat sheet
> - `test-cases.md` -- 12 structured test cases (TC-MF-001..012) covering lab bring-up, TN3270, TSO/ISPF, RACF enumeration, APF audit, dataset access, JCL submission, CICS, DB2, JES2, IRRDBU00, and SEAR API
> - `guides/mainframe-security-playbook.md` -- Deep-dive operational playbook covering z/OS architecture, lab construction, RACF methodology, real-world incidents, and defense patterns

## Summary

Mainframe security covers authorized penetration testing of IBM z/OS, z/VM, and z/VSE systems that still run the core transaction workloads for the global banking, insurance, airline, retail, and government sectors. Despite the "legacy" label, mainframes process the majority of the world's credit card transactions, social security records, and stock trades. A single compromised RACF user ID or APF-authorized library can expose millions of account records, defeat separation of duties, and enable persistent privileged access that survives normal patch cycles. This skill domain covers the specialized toolchain and methodology required to assess these environments: TN3270 terminal emulation, TSO/ISPF navigation, RACF user and group enumeration, APF (Authorized Program Facility) library audit, dataset access control testing, CICS transaction testing, JES2 job submission abuse, and the use of the IRRDBU00 database unload utility and the SEAR (Security API) REST interface for programmatic assessment.

**Domain**: mainframe

**MITRE ATT&CK**: TA0006-Credential Access, T1078-Valid Accounts, T1003-OS Credential Dumping

## Description

Mainframes occupy a peculiar position in the security landscape. They are simultaneously the most hardened general-purpose platforms ever shipped (hardware-assisted isolation via PR/SM, EBCDIC vs ASCII impedance mismatch, RACF mandatory access control, crypto express cards) and one of the most operationally fragile: the average z/OS system operator is older than the average red teamer, the skills gap is widening, and most internal pentest teams lack anyone who can credibly navigate ISPF. This makes mainframe assessments high-leverage. When a tester can reach a TN3270 session, read a `LISTUSER` dump, and audit APF libraries, they are often operating in a part of the estate that has not been independently tested in years.

The attack surface on z/OS differs fundamentally from Linux/Windows environments. There are no traditional "open ports" in the same sense; instead, there are subsystems (CICS, DB2, IMS, JES, VTAM, TSO, z/OSMF, FTP, HTTP) each fronted by RACF for authentication and resource authorization. A typical engagement proceeds by: (1) reaching the TN3270 listener or the z/OSMF REST API, (2) obtaining or guessing a low-privilege TSO user ID, (3) enumerating RACF users, groups, and dataset access rules, (4) auditing APF libraries for writable datasets that would grant authorized-program status, (5) escalating to SPECIAL or AUDITOR attribute holders, and (6) demonstrating impact by reading sensitive datasets or submitting privileged JCL.

This skill emphasizes realistic, authorized assessment techniques against lab targets built from freely available components: the Hercules open-source mainframe emulator running MVS 3.8j Tur(n)key 4- (TK4-) or MVSCE, the open-source SEAR project for RACF REST testing, and mainframed/Enumeration for scripted discovery. Commands and JCL examples reflect real z/OS syntax so that practitioners can move from the lab to a client engagement without relearning the grammar.

## Use Cases

1. **RACF User and Group Assessment** -- Enumerate user IDs via `LISTUSER` / `SEARCH`, dump group connectivity via `LISTGRP`, identify SPECIAL/AUDITOR/OPERATIONS attribute holders, and audit password rules and revoked-but-not-deleted accounts.
2. **APF Library Audit** -- Identify APF-authorized libraries (system and dynamic), check whether any are backed by user-writable datasets, and demonstrate the impact of planting a payload in an authorized library.
3. **Dataset Access Control Testing** -- Enumerate cataloged datasets via `LISTCAT`/`LISTDSN`, test READ/UPDATE/ALTER/CONTROL access rules via `PERMIT` review, and identify over-permissive UACC (universal access) settings.
4. **CICS Transaction Testing** -- Discover transaction codes via `CEDA VIEW`, test for unsigned or overridden transactions, and assess CICS Web Services and CICS TSQ/TDQ abuse.
5. **JES2/JES3 Job Submission** -- Review JOB card credentials, submit JCL via internal reader or `SUBMIT`, and test for job classes that allow execution outside intended windows.
6. **TN3270 Mainframe Pentest** -- Reach the TN3270 listener, negotiate terminal type, log on to TSO, navigate ISPF, and pivot to CICS/DB2/IMS as the user's access permits.
7. **JCL and Batch Code Review** -- Audit production JCL for hardcoded credentials, missing RACF `USER=`/`PASSWORD=` obfuscation, dataset disposition abuse, and unauthorized step library overrides.

## Core Tools

| Tool | Category | Purpose |
|------|----------|---------|
| mainframed/Enumeration | Enumeration | Open-source collection of REXX scripts and TSO commands for z/OS reconnaissance: user/group enumeration, APF list, dataset discovery, RACF info |
| SEAR (Mainframe-Renewal-Project) | API Testing | Security Environment for Auditing RACF -- REST API wrapper around native RACF services for programmatic user/group/dataset testing |
| IBM Security zSecure Audit | Audit | Commercial RACF audit and reporting suite; reference standard for client-side reporting and CARLa command generation |
| Zowe | Integration | Open-source framework for z/OS modernization; exposes z/OSMF REST APIs and CLI tooling for jobs, files, and datasets |
| Hercules | Emulator | Open-source System/370, ESA/390, and z/Architecture emulator; foundation for free MVS 3.8j (TK4-/MVSCE) mainframe labs |
| Tur(n)key 4- (TK4-) | Lab Distribution | Pre-built MVS 3.8j distribution for Hercules; free, runnable on commodity hardware; de facto standard mainframe learning lab |
| MVSCE | Lab Distribution | Community Edition MVS 3.8j distribution, alternative to TK4-; integrates tooling and sample datasets for security practice |
| x3270 / c3270 / wc3270 | Terminal | TN3270E terminal emulators (X/Windows, curses, Windows console); the canonical way to reach a mainframe session |
| tn3270 client (various) | Terminal | Any conformant TN3270 terminal emulator; alternatives include Vista, IBM Personal Communications, IBM Host On-Demand |
| RACF TSO commands | Auth & Access | `LISTUSER`, `LISTGRP`, `SEARCH`, `ADDUSER`, `ALTUSER`, `DELUSER`, `CONNECT`, `PERMIT`, `PASSWORD`, `SETROPTS` |
| ISPF / SDSF | Operator UI | Interactive System Productivity Facility (developer/operator UI); System Display and Search Facility (job, output, and log browsing) |
| CICS Explorer / CEDA | CICS Admin | CICS Transaction Server administration; CEDA (CICS Execution Definition Online) for resource definition and transaction discovery |
| IBM Health Checker for z/OS | Hardening | Native health-check framework; runs checks against z/OS Security Server, RACF, and z/OSMF; useful baseline for client-side hardening gaps |

## Methodology

### Phase 1: TN3270 Recon and Session Acquisition

Reach the mainframe's interactive surface and obtain an initial TSO session.

1. Identify TN3270 listeners (`nmap -p 23,992,1027 --script=tn3270-info`); record the VTAM applid and any banner text.
2. Connect with `x3270 host:port`, negotiate TN3270E, and capture logon screens (TSO, CICS, IMS, NATURAL).
3. Probe default logon IDs against the TSO logon panel (IBMUSER, SYSADM, ADCDA, et al.) using account-specific practices.
4. Enumerate z/OSMF REST endpoints (`https://host/zosmf/`) for jobs, files, and REST API info if the REST interface is reachable.
5. Record the security server banner (RACF vs ACF2 vs Top Secret); methodology below assumes RACF.

### Phase 2: User, Group, and Attribute Discovery

Map the identity and privilege landscape.

1. Run `LISTUSER *` (or `SEARCH FILTER(*)` for a thinner sweep) to enumerate user IDs, default groups, attributes, and last-change dates.
2. Run `LISTGRP *` to enumerate groups, owners, and connected users; identify the SYSADM and operations groups.
3. Filter for SPECIAL, AUDITOR, and OPERATIONS attribute holders; these are the RACF equivalent of Domain Admins.
4. Identify REVOKED users that have not been DELETED (often retain dataset ownership and group memberships).
5. Collect PASSDATE/PASSWORD-INTERVAL data to flag dormant accounts.

### Phase 3: RACF Testing -- Rules, Datasets, and Resources

Test the authorization layer against the enumerated user base.

1. Run `SEARCH CLASS(DATASET) FILTER(**)` to enumerate cataloged dataset profiles.
2. For each sensitive dataset pattern (`SYS1.**`, `PROD.**`, `PAYROLL.**`), review `LISTDSD` and `PERMIT` output for UACC and access list.
3. Identify datasets where UACC=READ/UPDATE/ALTER that should be NONE, and access list entries that grant broad group access.
4. Check the general resource classes (`FACILITY`, `TERMINAL`, `SURROGAT`, `STARTED`, `OPERCMDS`) for over-permissive profiles.
5. Document violations and propose `PERMIT` / `ALTDSD` fixes with least-privilege defaults.

### Phase 4: Dataset Access and APF Library Audit

Hunt for the highest-leverage escalation primitives on z/OS: writable datasets that back APF libraries.

1. Run `SETR LIST` to dump current APF list (system APF and dynamic APF).
2. For each APF library dataset, run `LISTDSD DATASET(...)` and verify UACC and access list; identify user-writable entries.
3. Cross-reference writeable APF datasets against the current user's group memberships; flag any effective write path.
4. Examine LINKLIST and LPA libraries for unauthorized additions; check `PROGxx` member additions.
5. Demonstrate (in lab) the planting of an authorized program in a writeable APF dataset; for client work, document the finding without execution.

### Phase 5: Privilege Escalation and Impact Demonstration

Convert the access-control findings into demonstrable impact.

1. Identify paths to SPECIAL/AUDITOR/OPERATIONS via group ownership chain abuse or SURROGAT class exploitation.
2. Read sensitive production datasets (read-only demonstration) to prove data exposure scope.
3. Submit benign JCL via internal reader or `SUBMIT` to demonstrate batch execution capability and JES2 class abuse.
4. Pivot to CICS or DB2 subsystems via stored user credentials and linked transaction configurations.
5. Compile findings, propose hardening (`ALTDSD`, `PERMIT`, `SETROPTS`, APF list cleanup, password policy), and document detection gaps in SMF/RACF audit.

## Practical Steps

### Step 1: Build a Mainframe Lab with Hercules and TK4-

The free, reproducible foundation for all mainframe skill practice.

```bash
# Debian/Ubuntu prerequisites
sudo apt-get install build-essential cmake libssl-dev flex bison git \
  autoconf automake libtool pkg-config

# Build Hercules from source
git clone --depth=1 https://github.com/SDL-Hercules-390/hyperion.git
cd hyperion
./util/bldcnf.pl   # generates configure
./configure --prefix=/opt/hercules
make -j"$(nproc)"
sudo make install

# Fetch TK4- (MVS 3.8j Tur(n)key 4-)
mkdir -p ~/mf-lab && cd ~/mf-lab
# Replace URL with the current mirror from the MVS turnkey forum
wget https://github.com/MVS-SOW/tk4-/archive/refs/heads/master.tar.gz
tar xzf master.tar.gz && cd tk4--master

# Start TK4- (Hercules reads hercules.cnf in this directory)
./mvs -t 3270-2   # local 3270 on port 3270-2
# In another terminal, connect with c3270:
c3270 localhost:3270
# At the logon panel, use the default TK4- credentials documented in README.md
```

### Step 2: Enumerate RACF Users via TSO Commands

Once logged into TSO, drop to READY and run RACF commands via IKJEFT01.

```ts
// At TSO READY prompt:
LISTUSER *                                /* every user defined to RACF */

// Narrow to attribute holders:
SEARCH FILTER(USER*) CLIST(NAME)          /* user IDs beginning with USER */

// Dump one user in detail:
LISTUSER IBMUSER                          /* attributes, groups, revoke info */

// Enumerate groups and their owners:
LISTGRP *                                 /* all groups */

// Find SPECIAL attribute holders:
SEARCH FILTER(*) CLIST(NAME)              /* grep for SPECIAL in output */
```

### Step 3: Audit APF Libraries

```ts
// Display current APF list (system + dynamic):
SETR LIST

// Sample output (abridged):
//   DSNAME(SYS1.LINKLIB) VOLUME(SYSRES) SMS=NO
//   DSNAME(SYS1.SVCLIB)  VOLUME(SYSRES) SMS=NO
//   DSNAME(MYUSER.LINKLIB) SMS=YES          <-- investigate

// For each APF dataset, examine access:
LISTDSD DATASET('MYUSER.LINKLIB') ALL

// Confirm UACC and access list; ANY user with UPDATE/ALTER is a finding.
// Look at PROGxx for dynamic APF additions:
//   In SYS1.PARMLIB(PROGxx)
//   APF ADDSET DSNAME(MYUSER.LINKLIB) SMS(**YES**) VOLUME(*)  /* red flag */
```

### Step 4: Use SEAR for Programmatic RACF Testing

```bash
# SEAR provides a REST wrapper around RACF services
# Deploy the SEAR server on z/OS (or zPDT) following the README
# Then query RACF objects from Kali:

# List users (REXX-style 'LISTUSER *' wrapped as REST)
curl -k -u "$SEAR_USER:$SEAR_PASS" \
  "https://mf-target/zosmf/api/rest/sear/users" \
  | jq '.users[] | {name: .name, attributes: .attributes}'

# List a specific dataset profile
curl -k -u "$SEAR_USER:$SEAR_PASS" \
  "https://mf-target/zosmf/api/rest/sear/datasets/SYS1.LINKLIB" \
  | jq '.access'

# Probe a group
curl -k -u "$SEAR_USER:$SEAR_PASS" \
  "https://mf-target/zosmf/api/rest/sear/groups/ADMGP" \
  | jq '.users[]'
```

### Defense Perspective

### Hardening RACF

- Enforce eight-character-or-greater passwords with mixed-case alpha-numeric-symbol composition; enable mixed-case via `SETROPTS PASSWORD(ALWNUMIC,ALWSYMBL,MIXEDCASE)`.
- Run `SETROPTS LIST` regularly and audit for insecure options (`SAUDIT`, `CMDVIOL`, `OPERAUDIT` enabled; `CATDSNS` sensible).
- Strip SPECIAL/AUDITOR attributes from non-essential user IDs; implement just-in-time elevation via secondary IDs.
- Delete REVOKED users promptly; they retain dataset ownership and group memberships until `DELUSER`.

### APF and Linklist Hygiene

- Restrict dynamic APF additions to controlled change windows; review `PROGxx` members at every change.
- Mark APF datasets as READ-only at the storage layer (RACF `UACC=READ`, DFSMS `ERASE`/`READPASS`).
- Periodically run IBM Health Checker `APF_CHECK` and reconcile against the gold source.

### Audit and Detection

- Enable SMF type 30 (job/step), 80 (RACF), 81 (RACF), and 83 (tape) records; ship to SIEM with timestamp, userid, and resource class.
- Implement `CMDVIOL` and `OPERAUDIT` so that command violations and operator actions are auditable.
- Forward RACF SMF to a separate LPAR or off-platform collector that the SPECIAL user on the assessed LPAR cannot alter.

### Encryption and Isolation

- Enable Coupling Facility (CF) encryption for shared DASD and CF structures.
- Use z/OS Encryption Readiness Technology (zERT) for in-flight TLS on FTP, TN3270, and z/OSMF.
- Isolate development and production LPARs via PR/SM and z/VM partitioning; never share DASD pools across trust boundaries.

### Multi-Level Security

- Where classification is required, use RACF MLS (Multi-Level Security) mode for labels and mandatory access control rather than discretionary UACC.
- Document SECLABEL ownership and review periodically; mis-assignment of a high-water-mark label defeats MLS.

## Detection Methods

### z/OS Audit Logs
- **SMF (System Management Facility)**: SMF records for auth (type 80), RACF commands (type 30, 81), APF (type 14, 15).
- **RACF SETR events**: Changes to RACF settings (e.g., `SETR NOOPERAUDIT` to disable auditing).
- **CICS audit**: CICS transient data destinations; transaction abuse signatures.
- **DB2 audit**: DB2 audit traces for unauthorized SELECT, COPY from SYSTEM tables.
- **JES2/JES3 spool access**: Unauthorized spool dataset access.

### SIEM Detection Rules
- **Splunk SPL (z/OS)**: `index=zos sourcetype=smf:80 | where event_type="AUTH_FAILURE" | stats count by userid`
- **Syncsort / IBM Security zSecure**: Mainframe SIEM integration.

## Defense Evasion Techniques

### RACF Stealth
- **Use legitimate RACF groups**: Don't create new user; abuse existing over-privileged group membership.
- **APF library abuse**: Add malicious load library to APF list; bypass RACF checks.
- **SETROPTS RACLIST abuse**: Modify in-storage RACF profiles; changes lost on restart.

### CICS Stealth
- **Transient data destinations**: Use legitimate TD queue to hide payload; blends with normal transactions.
- **Task control table manipulation**: Modify CICS TCT to hide malicious transactions.
- **Program control: NEWCOPY**: Replace legitimate CICS program at runtime via NEWCOPY; no program-level audit.

### DB2 Stealth
- **Bind abuse**: Bind malicious DBRM into existing package; bypasses audit.
- **Stored procedure persistence**: Backdoor stored procedure; activates on specific trigger.
- **Cursor manipulation**: Use sensitive cursor for slow data exfil; below query-rate threshold.

### JES2/JES3 Stealth
- **Spool dataset abuse**: Hide malicious JCL in spool dataset; appears as legitimate job.
- **Started task (STC) abuse**: Modify started task JCL; runs at IPL (boot) time.

## Differentiation

This is the only mainframe-focused skill domain in the workspace. Adjacent skills provide complementary coverage without overlap:

- **`ad-ldap-attack`** covers enterprise identity on Active Directory / LDAP, which is a separate identity stack from RACF/ACF2/Top Secret. Cross-domain (AD-to-mainframe) trust analysis is the boundary between the two skills.
- **`database-attack`** covers RDBMS exploitation generally (MSSQL, Oracle, PostgreSQL); DB2 for z/OS specifics (plan/package security, DB2I, SPUFI) live here.
- **`network-pentest`** and **`network-sniffing-mitm`** cover the IP network that fronts TN3270 and z/OSMF; this skill picks up at the TN3270 session itself.
- **`osint`** may surface mainframe indicators (JOB card credentials in source repositories, IBM doc leaks) that feed into this skill's enumeration phase.

No other skill covers RACF, APF, CICS, JES2, or z/OS dataset access control. The mainframe ecosystem is sufficiently distinct (EBCDIC, JCL, REXX, ISPF) that the techniques do not transfer cleanly from Unix/Windows pentest skills.
