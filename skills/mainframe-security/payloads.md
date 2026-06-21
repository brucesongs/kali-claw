# Mainframe Security Payloads

> This file is a companion to `SKILL.md`, organizing common commands, JCL, and scripts for IBM z/OS, RACF, CICS, DB2, JES2, and related mainframe security testing.
> Purpose: Quickly find a technique for an authorized assessment, ready to copy for lab or client work.
> All payloads are for authorized security testing only. Do not run against production mainframes without explicit written authorization.

---

## Index

1. [Mainframe Ecosystem](#1-mainframe-ecosystem)
2. [Lab Setup](#2-lab-setup)
3. [TN3270 Connection](#3-tn3270-connection)
4. [TSO/ISPF Navigation](#4-tsoispf-navigation)
5. [RACF Fundamentals](#5-racf-fundamentals)
6. [RACF Command Reference](#6-racf-command-reference)
7. [APF Library Audit](#7-apf-library-audit)
8. [Dataset Access Control](#8-dataset-access-control)
9. [JCL Submission](#9-jcl-submission)
10. [CICS Transaction Testing](#10-cics-transaction-testing)
11. [DB2 for z/OS](#11-db2-for-zos)
12. [SNA and AppC](#12-sna-and-appc)
13. [JES2/JES3 Job Submission](#13-jes2jes3-job-submission)
14. [RACF Database Extraction](#14-racf-database-extraction)
15. [SEAR API Usage](#15-sear-api-usage)
16. [z/OSMF REST API](#16-zosmf-rest-api)
17. [Detection (Blue Side)](#17-detection-blue-side)
18. [Quick Reference Cheat Sheet](#18-quick-reference-cheat-sheet)

---

## 1. Mainframe Ecosystem

### IBM z Series Hardware Generations

Modern IBM Z hardware is the current generation of the System/360 bloodline. Banks, insurers, and governments run z15, z16, and (as of 2026) the successor generation on production LPARs.

```text
// Hardware reference
zBC12 / zEC12 (2010-2013)   -- end of marketing, end of service
z13      (2015)             -- end of standard support
z14      (2017)             -- pervasive encryption era
z15      (2019)             -- Data Privacy Passports, CF encryption
z16      (2022)             -- on-chip AI inferencing, quantum-safe
LinuxONE III/IV/V            -- Linux-only z hardware variant
zPDT   (IBM Z Personal Development Test)  -- licensed dev/test on x86
```

### z/OS, z/VM, z/VSE, and MVS

```text
// Operating systems that run on Z hardware
z/OS    -- the flagship; Unix + MVS, RACF, JES2/JES3, CICS, DB2, IMS
z/VM    -- hypervisor; hosts Linux on Z and (rarely) z/VSE guests
z/VSE   -- smaller-footprint MVS-like; common in retail
z/TPF   -- Transaction Processing Facility; airlines, large banks
MVS 3.8j -- public-domain-ish vintage MVS; what TK4-/MVSCE runs
Linux on Z (SUSE, RHEL, Ubuntu)  -- runs natively or under z/VM
```

### Subsystems That Matter for Security

```text
// z/OS subsystems and their security relevance
TSO/E   -- interactive Time Sharing Option; user-facing shell
ISPF    -- Interactive System Productivity Facility; TSO UI
JES2/JES3 -- Job Entry Subsystem; batch and print spooler
CICS    -- Customer Information Control System; OLTP workhorse
IMS     -- Information Management System; DB/DC for banking
DB2     -- relational database; covered in section 11
VTAM    -- Virtual Telecommunications Access Method; SNA + TN3270
RACF    -- Resource Access Control Facility; the security server
z/OSMF  -- z/OS Management Facility; REST API front door
```

### Why This Matters for Assessors

```text
// The skill gap is real
- Most red teams lack any mainframe experience
- Most mainframe operators lack recent security training
- A pentester who can run LISTUSER and audit APF adds unique value
- Engagement scoping must distinguish:
    * interactive (TSO/CICS)   -- this skill
    * batch (JES2/JCL)         -- this skill
    * database (DB2/IMS)       -- partial; combine with database-attack
    * network (TN3270/VTAM)    -- start here for entry
```

---

## 2. Lab Setup

### Build Hercules on Debian/Ubuntu

Hercules is the open-source emulator that powers every free mainframe lab.

```bash
# Prerequisites
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev flex bison \
  git autoconf automake libtool pkg-config zlib1g-dev

# Clone and build SDL-Hercules-390 (Hyperion)
git clone --depth=1 https://github.com/SDL-Hercules-390/hyperion.git
cd hyperion
./util/bldcnf.pl                # generates ./configure
./configure --prefix=/opt/hercules
make -j"$(nproc)"
sudo make install

# Verify
hercules --version
```

### Build Hercules on macOS

```bash
# Xcode command line tools required
xcode-select --install

# Install dependencies via Homebrew
brew install autoconf automake libtool pkg-config openssl@3

# Build
git clone --depth=1 https://github.com/SDL-Hercules-390/hyperion.git
cd hyperion
./util/bldcnf.pl
./configure --prefix=/opt/hercules \
  --with-openssl=$(brew --prefix openssl@3)
make -j"$(sysctl -n hw.ncpu)"
sudo make install
```

### Fetch TK4- (MVS 3.8j Turnkey)

TK4- is the de facto free MVS distribution. The community maintains it on GitHub and the Open Mainframe Project mirrors.

```bash
# Replace the URL with the current community mirror
mkdir -p ~/mf-lab && cd ~/mf-lab
git clone --depth=1 https://github.com/MVS-SOW/tk4-.git
cd tk4-

# Inspect the README for current default ports and credentials
less README.md

# Start TK4- (the ./mvs script launches hercules with hercules.cnf)
./mvs
# Expect: MVS messages on console; system enters wait state ready for logons
```

### Alternative: MVSCE

MVSCE (Community Edition) is an alternative distribution with newer tooling.

```bash
mkdir -p ~/mf-lab && cd ~/mf-lab
git clone --depth=1 https://github.com/MVS-SOW/MVSCE.git
cd MVSCE
./mvs
```

### Connect with c3270

```bash
# c3270 is a curses-based TN3270 client; available in most distros
sudo apt-get install -y c3270

# Connect to the local Hercules TN3270 listener (default port 3270)
c3270 localhost:3270

# Connect to a remote target (authorized testing only)
c3270 target.example.com:23
```

### Connect with x3270

```bash
# x3270 is the X11 variant
sudo apt-get install -y x3270

# Connect
x3270 localhost:3270
```

### Docker Option: Containerized Hercules + TK4-

```bash
# Community-maintained Dockerfile; review before use
# Search: 'kubectl apply -f' for mainframe-on-k8s experiments
docker pull REPLACE_WITH_YOUR_MF_IMAGE:latest
docker run -d --name mf-lab -p 3270:3270 \
  -v "$HOME/mf-lab/tk4-":/tk4 REPLACE_WITH_YOUR_MF_IMAGE:latest
c3270 localhost:3270
```

---

## 3. TN3270 Connection

### Probe a TN3270 Listener with Nmap

```bash
# Identify TN3270 listeners on common ports
nmap -p 23,992,1027,17500 -sV target.example.com

# Use the tn3270-info NSE script if available
nmap -p 23 --script=tn3270-info target.example.com

# Brute-force VTAM applid (if NSE script absent, manual)
nmap -p 23 --script=tn3270-screen target.example.com
```

### Connect with c3270 and Capture Banner

```bash
# Basic connect
c3270 target.example.com:23

# Trace the negotiation (useful for assessment documentation)
c3270 -trace target.example.com:23

# Save trace to file
c3270 -trace -tracefile ./tn3270.trace target.example.com:23
```

### Connect with x3270 and Script

x3270 supports a scripting mode that lets you drive the session from the shell. Useful for automating repetitive enumeration.

```bash
# Run a script against the session
x3270 -script target.example.com:23 <<'EOF'
String(LOGON)
Enter
Expect("Userid")
String(IBMUSER)
Enter
Expect("Password")
String(REPLACE_WITH_YOUR_PASSWORD)
Enter
Expect("READY")
Ascii > session.log
Quit
EOF
```

### Connect over TLS (TN3270E over TLS)

```bash
# Production mainframes increasingly enforce TLS on the TN3270 listener
c3270 -tls target.example.com:992

# Verify certificate
openssl s_client -connect target.example.com:992 -showcerts
```

### Banner Grepping

```bash
# Capture the post-negotiation banner text from a trace
grep -a "WELCOME\|LOGON\|CICS\|TSO\|IMS\|VM/370\|z/OS" tn3270.trace | sort -u
```

---

## 4. TSO/ISPF Navigation

### TSO Logon Panel

```text
// The classic VTAM logon panel
WELCOME TO THE MVS SYSTEM
ENTER LOGON PARAMETERS BELOW:

USERID    ===> IBMUSER
PASSWORD  ===.
PROCEDURE ===> IKJACCNT
ACCT NMBR ===> ACCT#
SIZE      ===> 4096
COMMAND   ===> ISPF

ENTER LOGON PARAMETERS:
```

### TSO READY Prompt Basics

```ts
// Once authenticated, TSO shows "READY"
TIME                     /* show current date and time           */
PROFILE                  /* show terminal profile (W/H, etc.)    */
WHO                      /* show current user ID                 */
LISTBC                   /* list broadcast messages              */
SEND 'hi',USER(IBMUSER)  /* send a TSO message                   */
LOGOFF                   /* end the session                      */
```

### Launch ISPF

```ts
// From READY
ISPF                     /* launches the Primary Option Menu    */

// ISPF Primary Option Menu (typical)
Option  ===> __
   0  Settings      Terminal and user parameters
   1  View          Display source data or listings
   2  Edit          Create or change source data
   3  Utilities     Perform utility functions
   4  Foreground    Interactive compile, link, and run
   5  Batch         Submit compile, link, and run
   6  Command       Enter TSO or workstation commands
   7  Dialog Test   Perform dialog testing
   8  LM Facility   Library administrator functions
   9  IBM Products  IBM program development products
   10 SCLM          SW configuration & library manager
   11 Workplace     ISPF Object/Action Workplace
   M  More          Additional IBM products
   X  Exit          Terminate ISPF using log/list defaults
```

### ISPF DSLIST (Dataset List)

```ts
// In ISPF option 3.4
DSNAME LEVEL ===> SYS1.*

// Returns cataloged datasets matching the pattern
```

### ISPF Command Shell (Option 6)

```ts
// In ISPF option 6, run any TSO command interactively
LISTUSER IBMUSER
LISTGRP *
SETR LIST
```

### ISPF Browsing a Dataset

```ts
// In ISPF option 1 (View)
VIEW DATASET('SYS1.PROCLIB(IEFPROC)')

// Or from option 3.4, type 'B' next to the dataset
```

---

## 5. RACF Fundamentals

### User and Group Concepts

```text
// RACF mental model
USERID    -> uniquely identifies a person or started task
GROUP     -> collect users; the DEFAULT group is the CONNECT group
ATTRIBUTE -> SPECIAL, AUDITOR, OPERATIONS, REVOKE, etc.
DATASET PROFILE -> protects a dataset (or pattern) by HLQ
GENERAL RESOURCE PROFILE -> protects a non-dataset resource (TERMINAL, FACILITY, etc.)
UACC      -> Universal Access (NONE, READ, UPDATE, ALTER, CONTROL, EXECUTE)
ACCESS LIST -> per-user or per-group overrides on UACC
```

### LISTUSER: The Workhorse

```ts
// At READY or in ISPF option 6
LISTUSER *               // every user in RACF

LISTUSER IBMUSER         // single user detail

LISTUSER SYS*            // wildcard

// Sample abridged output:
//   USER=IBMUSER  NAME=IBM DEFAULT USER  OWNER=IBMUSER  CREATE-DATE=...
//     DEFAULT-GROUP=SYS1  PASSDATE=...  PASS-INTERVAL= 30
//     ATTRIBUTES=SPECIAL OPERATIONS AUDITOR
//     REVOKE DATE=NONE   LAST-ACCESS=...
//     GROUP-CONNECTIONS...
//     ...
```

### LISTGRP: Group Inventory

```ts
LISTGRP *                // every group in RACF

LISTGRP SYS1             // single group detail

// Sample output includes OWNER, SUPGROUP, CONNECTS list, TERMINAL UACC, etc.
```

### SEARCH: Filtered Enumeration

```ts
SEARCH FILTER(USER*) CLIST(NAME)         // names starting with USER
SEARCH FILTER(*ADM*) CLIST(NAME)         // names containing ADM
SEARCH CLASS(DATASET) FILTER(SYS1.**)    // dataset profiles matching SYS1.**
SEARCH CLASS(FACILITY) FILTER(**)        // every FACILITY profile
```

### Finding SPECIAL/AUDITOR/OPERATIONS Holders

```ts
LISTUSER *                                // pipe to a dataset
// Then offline grep:
//   SPECIAL  -> RACF admins; can modify any profile
//   AUDITOR  -> can audit; can read SMF/RACF audit data
//   OPERATIONS -> can manipulate datasets regardless of access list
```

### Identifying Dormant Users

```ts
// Listuser output includes LAST-ACCESS
// Flag any user where LAST-ACCESS is older than the corporate policy
// Example finding: IBMUSER LAST-ACCESS=2019-03-12, but REVOKED=NO
```

---

## 6. RACF Command Reference

### ADDUSER: Create a New User

```ts
ADDUSER MYUSER
  NAME('Test User')
  OWNER(SYSADM)
  DFLTGRP(SYS1)
  PASSWORD(REPLACE_WITH_INITIAL_PASSWORD)
  PASSDATE(0)
  NOREVOKE
  ATTRIBUTES(NONE)
  DATA('created by pentest engagement YYYYMMDD')
```

### ALTUSER: Modify a User

```ts
ALTUSER MYUSER PASSWORD(NEWPASS) PASSDATE(0)
ALTUSER MYUSER SPECIAL          // grant SPECIAL (authorized change only)
ALTUSER MYUSER NOSPECIAL        // revoke SPECIAL
ALTUSER MYUSER REVOKE           // revoke the user (cannot log on)
ALTUSER MYUSER NOREVOKE         // restore
```

### DELUSER: Remove a User

```ts
// Best practice: REVOKE first, observe for 30 days, then DELUSER
ALTUSER MYUSER REVOKE
// ... observe ...
DELUSER MYUSER
```

### PASSWORD: Reset Password

```ts
PASSWORD USER(MYUSER)            // prompt for new password
PASSWORD INTERVAL(30)            // change global password interval
PASSWORD HISTORY(8)              // remember last 8 passwords
PASSWORD RULES((ALPHANUM))       // enable mixed-case alphanumeric
```

### CONNECT: Group Membership

```ts
// Add MYUSER to GRP01 with USE attribute
CONNECT USERID(MYUSER) GROUP(GRP01)
CONNECT USERID(MYUSER) GROUP(GRP01) AUTHORITY(JOIN)
CONNECT USERID(MYUSER) GROUP(GRP01) AUTHORITY(CONNECT)
CONNECT USERID(MYUSER) GROUP(GRP01) AUTHORITY(CREATE)
```

### REMOVE: Group Removal

```ts
REMOVE USERID(MYUSER) GROUP(GRP01)
```

### ADDGROUP, ALTGROUP, DELGROUP

```ts
ADDGROUP GRP01 OWNER(SYSADM) SUPGROUP(SYS1) DATA('...')
ALTGROUP GRP01 OWNER(SYSADM)
DELGROUP GRP01
```

### ADDSD, ALTDSD, DELDSD: Dataset Profiles

```ts
ADDSD 'PROD.PAYROLL.**'
  OWNER(PAYADM)
  UACC(NONE)
  DATA('Payroll production datasets')

ALTDSD 'PROD.PAYROLL.**' UACC(NONE)

PERMIT 'PROD.PAYROLL.**' CLASS(DATASET) ID(PAYGROUP) ACCESS(READ)
PERMIT 'PROD.PAYROLL.**' CLASS(DATASET) ID(PAYADM)  ACCESS(ALTER)

DELDSD 'PROD.PAYROLL.**'
```

### SETROPTS: RACF System Options

```ts
SETROPTS LIST                    // show current options
SETROPTS PASSWORD(INTERVAL(30))  // password interval
SETROPTS PASSWORD(RULES((ALPHANUM)))
SETROPTS AUDIT                   // audit on by default
SETROPTS SAUDIT                  // audit SPECIAL attribute use
SETROPTS CMDVIOL                 // audit command violations
SETROPTS OPERAUDIT               // audit OPERATIONS attribute use
```

### SETR: Refresh the APF List (Dynamic)

```ts
SETR LIST                        // dump current APF list
SETR FORMAT                      // reformat RACF database (destructive; rarely)
```

---

## 7. APF Library Audit

### What is APF?

```text
// APF = Authorized Program Facility
// Programs in APF-authorized libraries run in authorized state (bit 0 of PSW).
// A write to an APF dataset is the z/OS analog of writing a kernel-mode driver.
// Find: APF dataset + writable by a non-operations user == CRITICAL finding.
```

### Dump the APF List

```ts
// At READY or ISPF option 6
SETR LIST

// Sample output (abridged):
//   ACTIVE SETTINGS
//   ...
//   APF LIST:
//     DSNAME(SYS1.LINKLIB)              VOLUME(SYSRES) SMS=NO
//     DSNAME(SYS1.SVCLIB)               VOLUME(SYSRES) SMS=NO
//     DSNAME(SYS1.LPALIB)               VOLUME(SYSRES) SMS=NO
//     DSNAME(SYS1.MIGLIB)               VOLUME(SYSRES) SMS=NO
//     DSNAME(SYS1.CSSLIB)               VOLUME(SYSRES) SMS=NO
//     DSNAME(MYUSER.LINKLIB)            SMS=YES         <-- INVESTIGATE
//     DSNAME(PROD.AUTHLIB)              SMS=YES
//   ...
```

### Audit Each APF Dataset

```ts
// For every DSNAME in the APF list:
LISTDSD DATASET('MYUSER.LINKLIB') ALL

// Look for:
//   UACC > READ                    <-- finding
//   ACCESS LIST has UPDATE/ALTER   <-- finding
//   ANY user not in operations     <-- finding
```

### Find Dynamic APF Entries (PROGxx)

```ts
// PROGxx is the source of dynamic APF additions
// Look in SYS1.PARMLIB(PROGxx) for APF ADD statements
// (In ISPF option 3.4, view SYS1.PARMLIB and search for PROGxx)

// Sample PROGxx snippet (red flag):
//   APF ADDSET DSNAME(MYUSER.LINKLIB) VOLUME(*) SMS(YES)
```

### Cross-Reference with LINKLIST and LPA

```ts
// LPA (Link Pack Area) libraries are loaded at IPL
// LINKLIST is the search order for programs
// Either can be abused to introduce unauthorized code
// In ISPF, browse SYS1.PARMLIB(LNKLSTxx) and (LPALSTxx)

// Sample LNKLSTxx:
//   LNKLST DEFINE NAME(CURRENT)                  /* default list   */
//   LNKLST ADD NAME(CURRENT) DSNAME(SYS1.LINKLIB) ENTRYPOINT(IRXEXEC)
//   LNKLST ADD NAME(CURRENT) DSNAME(MYUSER.LINKLIB)  <-- investigate
```

### Demonstrate (Lab Only) the Primitive

```text
// DO NOT execute on client systems without explicit authorization.
// In a lab (TK4-/MVSCE), you can demonstrate:
//   1. Write an authorized assembler program to MYUSER.LINKLIB
//   2. Issue LINK or ATTACH from TSO to invoke it
//   3. Show that it runs authorized and can, e.g., extract RACF in-storage data
// On client engagements, stop at the audit and document the primitive.
```

---

## 8. Dataset Access Control

### LISTCAT: Catalog Enumeration

```ts
// From ISPF option 3.4 or READY:
LISTCAT LEVEL(SYS1)             // catalog entries with HLQ SYS1

// Sample output:
//   NONVSAM ------- SYS1.PARMLIB
//     IN-CAT --- CATALOG.MASTER.VSAMS
//   NONVSAM ------- SYS1.PROCLIB
//   ...
```

### LISTDSN: Dataset Information

```ts
LISTDSN 'SYS1.PARMLIB'          // volume, DCB, etc.
LISTDSN 'SYS1.PARMLIB' HISTORY  // creation date, etc.
LISTDSN 'SYS1.PARMLIB' LEVEL    // allocation details
```

### IKJEFT01: TSO Batch

IKJEFT01 is the TSO batch terminal program; it lets you run TSO/RACF commands in batch.

```jcl
//RUNTSO  JOB (ACCT),'TSO BATCH',CLASS=A,MSGCLASS=X
//STEP01  EXEC PGM=IKJEFT01
//SYSTSPRT DD SYSOUT=*
//SYSTSIN  DD *
LISTUSER *
PROFILE
/*
```

### Submit IKJEFT01 with RACF Commands

```jcl
//RACFDMP  JOB (ACCT),'RACF DUMP',CLASS=A,MSGCLASS=X
//STEP01  EXEC PGM=IKJEFT01
//SYSTSPRT DD SYSOUT=*
//SYSTSIN  DD *
LISTUSER *
LISTGRP *
SETR LIST
/*
```

### PERMIT Review

```ts
// For each sensitive dataset, review its access list
LISTDSD DATASET('PROD.PAYROLL.**') ALL
// Sample output:
//   ...
//   UNIVERAL ACCESS = NONE
//   AUDIT = NONE
//   ACCESS LIST:
//     ID(PAYGROUP)  ACCESS(READ)     ACCESS(READ)
//     ID(PAYADM)    ACCESS(ALTER)    ACCESS(ALTER)
//     ID(*)         ACCESS(NONE)     ACCESS(NONE)
//   ...
```

### Attempt READ Access (Verify the Access List)

```ts
// Allocate a test dataset referencing the protected one
ALLOC DD(TEST) DA('PROD.PAYROLL.MASTER') SHR
// A successful open contradicts the expected UACC=NONE finding
// An ICH408I in the JES2 output indicates access was denied (expected)
```

### ALTDSD: Tighten a Profile

```ts
ALTDSD 'PROD.PAYROLL.**' UACC(NONE)
ALTDSD 'PROD.PAYROLL.**' AUDIT(ALL(READ(UPDATE(ALTER))))
PERMIT 'PROD.PAYROLL.**' CLASS(DATASET) ID(BADGRP) ACCESS(NONE)
```

---

## 9. JCL Submission

### JCL Anatomy

```jcl
// JOB card:      //JOBNAME JOB (ACCT),'COMMENT',CLASS=A,MSGCLASS=X
// EXEC card:     //STEP    EXEC PGM=IEBGENER,REGION=4096K
// DD statement:  //SYSUT2  DD SYSOUT=*
// Null card:     //
```

### Submit JCL from ISPF

```text
// In ISPF option 3.4:
//   - Browse the dataset
//   - Type SUBMIT on the command line
//   - The job is submitted to JES2
//   - Note the JOBID returned (JOB12345)
```

### Submit JCL from READY

```ts
SUBMIT 'IBMUSER.JCL(TEST)'      // submit a JCL member
SUBMIT 'MY.JCL(MEMBER1)'        // returns a JOBID
```

### Submit via Internal Reader

```ts
// Internal reader: a dataset allocated to DDname INTERNALRF
// is read by JES as if it were a card reader
ALLOC FILE(INTERNxx) DA('MY.JCL(MEMBER1)') SHR RECFM(F,B) LRECL(80)
// Or via SYNCSORT/IEBGENER to INTERNALRF
```

### JOB Card Review

```text
// Common findings in JOB cards:
//   1. Hardcoded USER= and PASSWORD=       <-- critical
//   2. CLASS= that bypasses default routing <-- medium
//   3. Missing accounting info             <-- low
//   4. REGION=0 (unlimited)                <-- low/medium
//   5. TIME=NOLIMIT                        <-- low/medium
//   6. COND= logic that suppresses abends  <-- medium (hides failures)
```

### Sample Benign JCL for Engagement

```jcl
//BENCHJOB JOB (ACCT),'BENCH',CLASS=A,MSGCLASS=X,NOTIFY=&SYSUID
//STEP01  EXEC PGM=IEBGENER
//SYSPRINT DD SYSOUT=*
//SYSIN    DD DUMMY
//SYSUT1   DD *
HELLO FROM AUTHORIZED ASSESSMENT
/*
//SYSUT2   DD SYSOUT=*
```

### IKJEFTE: Submit TSO Commands in Batch

```jcl
//TSOBATCH JOB (ACCT),'TSO',CLASS=A,MSGCLASS=X
//STEP01  EXEC PGM=IKJEFT01,DYNAMNBR=50
//SYSTSPRT DD SYSOUT=*
//SYSTSIN  DD *
PROFILE
TIME
LISTUSER &
SYSUID
/*
```

---

## 10. CICS Transaction Testing

### CEDA: Transaction Discovery

```text
// From a CICS terminal:
CEDA VIEW GROUP(*)             // view all installed groups
CEDA LIST TRANSACTION(*)       // list all transactions
CEDA VIEW TRANSACTION(****)    // view all transactions by mask
CEDA VIEW TRANSACTION(PAY?)    // wildcard
```

### Sign On to CICS (CESN)

```text
// At the CICS welcome panel:
CESN                          // sign-on transaction
// Enter RACF user ID and password
// On success, you are signed on to CICS under that user ID
```

### Discover Unsigned Transactions

```text
// In CEDA output, look for:
//   CMDPROT = NONE  -- transaction can issue supervisor calls
//   ROUTING = YES   -- transaction can route to other regions
//   TASKREQ = NO    -- task not required to be defined
// Each is a potential finding; document for follow-up
```

### CICS Web Services

```text
// CICS TS supports SOAP/REST web services via the CICS WS binding
// Look in CICS Explorer under "Web Services" for unsigned handlers
// Findings:
//   - Service exposed without RACF TICS protection
//   - SOAP service without message-level encryption
//   - REST endpoint mapping to a privileged CICS program
```

### CICS TSQ and TDQ

```text
// TSQ = Temporary Storage Queue
// TDQ = Transient Data Queue
// Both can be abused to store or pass data between transactions
// Findings: queues accessible to broad user population, or with sensitive data
```

### CEMT: Master Terminal

```text
// CEMT is the CICS master terminal transaction
// In authorized testing, CEMT can:
//   - Set transactions enabled/disabled
//   - Display tasks, files, programs, transactions
//   - Force shutdown of CICS
CEMT INQUIRE TASK
CEMT INQUIRE TRANSACTION(*)
CEMT INQUIRE FILE(*)
```

### CICS Resource Class

```ts
// RACF uses several classes for CICS:
//   TRANSACTION  -- transaction IDs (CICS transids)
//   TICS         -- transaction-level security
//   FACILITY     -- CICS facilities
//   TCICSTRN     -- alternate transid class (some sites use this)
// Enumerate profiles:
SEARCH CLASS(TRANSACTION) FILTER(**)
SEARCH CLASS(TICS) FILTER(**)
```

---

## 11. DB2 for z/OS

### DB2I Menu

```ts
// From TSO READY:
DSN                           // invokes DB2I panel
// DB2I Primary Option Menu
//   1  SPUFI
//   2  DCLGEN
//   3  BIND/REBIND
//   4  PROGRAM PREPARATION
//   5  RUN
//   ...
```

### SPUFI: Execute SQL Interactively

```ts
// From DB2I option 1 (SPUFI):
//   INPUT DATASET  ===> IBMUSER.SPUFI.IN
//   OUTPUT DATASET ===> IBMUSER.SPUFI.OUT
//   CHANGE DEFAULTS ===> YES
//   ...
// Author your SQL in the input dataset, then run

SELECT CURRENT SQLID, CURRENT SERVER, CURRENT TIMESTAMP
  FROM SYSIBM.SYSDUMMY1;
```

### Enumerate Grants via SYSIBM Catalog

```sql
-- Users and their DB2 primary auth IDs
SELECT GRANTOR, GRANTEE, NAME, OWNER
  FROM SYSIBM.SYSTABAUTH
 WHERE TCREATOR = 'SYSIBM';

-- Find PUBLIC grants on sensitive tables
SELECT GRANTEE, NAME, TCREATOR, COLLATION
  FROM SYSIBM.SYSTABAUTH
 WHERE GRANTEE = 'PUBLIC';

-- Plan and package security
SELECT NAME, OWNER, CREATOR
  FROM SYSIBM.SYSPLAN;
SELECT COLLID, NAME, OWNER
  FROM SYSIBM.SYSPACKAGE;
```

### Bind and Rebind

```ts
// In DB2I option 3:
BIND PLAN(MYPLAN) MEMBER(MYMODULE) -
     ACTION(REPLACE) -
     ISOLATION(CS) -
     VALIDATE(BIND)
```

### DB2 RACF Classes

```ts
// RACF protects DB2 via classes:
//   DSNADM    -- DB2 administrative authority
//   DSNB      -- DB2 buffer pool
//   DSNR      -- DB2 resource (DB, table, plan)
//   MDSNMBR   -- DB2 member
// Enumerate profiles:
SEARCH CLASS(DSNR) FILTER(**)
```

---

## 12. SNA and AppC

### What Is SNA?

```text
// SNA = Systems Network Architecture
// IBM's pre-IP networking protocol; still in production for some banks
// AppC (Advanced Program-to-Program Communication) = LU6.2 over SNA
// VTAM = Virtual Telecommunications Access Method (the z/OS SNA stack)
// NetView = SNA network management
```

### VTAM APPL Definitions

```text
// In SYS1.VTAMLST(APPLSTxx):
//   APPL statements define LUs (logical units) such as CICS, TSO, IMS
//   Each APPL has a name (the VTAM applid seen at the TN3270 logon panel)
// Findings:
//   - APPL without UACC=READ (broad access)
//   - APPL bound to a default logon mode that bypasses RACF
```

### LU6.2 (AppC) Sessions

```text
// AppC pairs are defined via side information profiles
// Look in SYS1.APPCTP (or local equivalent)
// Test: can an unauthorized LU6.2 conversation be initiated?
//   - Tool: AFTP, APPC Sample Conversation (z/OS Communications Server)
//   - Finding: LU6.2 pair without RACF conversation security
```

### NetView

```text
// NetView is the SNA network management console
// Findings:
//   - Default NETVIEW user ID with default password
//   - Operator IDs with broad command authority
//   - CNM (communication network management) data exposed
```

### RACF Classes for SNA

```ts
//   TERMINAL  -- non-SNA and SNA terminals
//   APPCLU    -- logical units
//   APPCTP    -- transaction programs
//   APPCSI    -- side information
//   LUMODE    -- logon modes
SEARCH CLASS(APPCLU) FILTER(**)
SEARCH CLASS(APPCTP) FILTER(**)
```

---

## 13. JES2/JES3 Job Submission

### JES2 SDSF Panels

```text
// In ISPF, navigate to SDSF (option =M.5 or SDSNF at READY)
// Primary panels:
//   I  -- input queue      (jobs waiting to execute)
//   DA -- display active   (running jobs)
//   ST -- status           (job status: output, waiting)
//   O  -- output           (completed jobs, spool output)
//   H  -- held output
//   LOG -- system log
```

### Filter and Browse

```text
// In SDSF ST panel:
PREFIX *                    // all jobs
OWNER *                     // all owners
FILTER JOBID EQ J*          // job IDs starting with J
FILTER USERID EQ IBMUSER    // jobs owned by IBMUSER
SORT JOBNAME A              // sort by job name

// Open a job's output with ?
// Navigate spool files with S (select), then browse with ?
```

### JES2 Operator Commands

```text
// $D JOB,Q -- display job queue
// $D JOB,JOBID=JOB12345 -- display specific job
// $C JOB,JOBID=JOB12345 -- cancel job
// $P JOB,JOBID=JOB12345 -- purge job (remove from spool)
// $D U --> display device status
// $D SPOOLDEF -- display spool configuration

// These typically require OPERATIONS attribute; document attempts.
```

### JES2 Internal Reader

```text
// The internal reader lets you submit JCL programmatically
// Common abuse: a low-priv user writes JCL to a dataset, then has
//   the reader ingest it. The JOB card determines whose privileges apply.
// Findings:
//   - Internal reader class too permissive
//   - JOB card with USER= overrides that should be blocked
//   - Surrogate (SURROGAT class) profiles that are too broad
```

### JES3 Differences

```text
// JES3 is the less-common JES variant; has its own command set
//   *START   -- start JES3
//   *INQUIRY -- job inquiry
//   *CANCEL  -- cancel job
// Most engagements will encounter JES2; JES3 appears in larger shops.
```

---

## 14. RACF Database Extraction

### IRRDBU00: The Database Unload Utility

IRRDBU00 unloads the RACF database to a sequential file for offline analysis. It is the canonical baseline-capture tool.

```jcl
//IRRDBU00 JOB (ACCT),'RACF UNLOAD',CLASS=A,MSGCLASS=X
//STEP01  EXEC PGM=IRRDBU00,PARM=NOLOCKINPUT
//SYSPRINT DD SYSOUT=*
//INDD    DD DSN=SYS1.RACF.DB,DISP=SHR
//OUTDD   DD DSN=&HLQ..RACFDB.UNLOAD,
//           DISP=(NEW,CATLG),SPACE=(CYL,(50,50)),
//           DCB=(RECFM=VB,LRECL=4096,BLKSIZE=0)
//SYSIN   DD *
NOLOCKINPUT
/*
```

### IRRUT100: Verify RACF Database Integrity

```jcl
//IRRUT100 JOB (ACCT),'RACF VERIFY',CLASS=A,MSGCLASS=X
//STEP01  EXEC PGM=IRRUT100
//SYSPRINT DD SYSOUT=*
//SYSUT1  DD DSN=SYS1.RACF.DB,DISP=SHR
```

### IRRADU00: Audit Record Unload

```jcl
//IRRADU00 JOB (ACCT),'RACF AUDIT UNLOAD',CLASS=A,MSGCLASS=X
//STEP01  EXEC PGM=IRRADU00
//SYSPRINT DD SYSOUT=*
//INDD    DD DSN=SYS1.MAN1,DISP=SHR   // SMF dump (type 80/81)
//OUTDD   DD DSN=&HLQ..RACF.AUDIT.UNLOAD,
//           DISP=(NEW,CATLG),SPACE=(CYL,(50,50)),
//           DCB=(RECFM=VB,LRECL=4096,BLKSIZE=0)
```

### Parsing the Unload

```bash
# The IRRDBU00 output is structured; parse with awk/jq after converting
# Community parsers exist; here is a sketch

# Step 1: download the unload file (binary, VB, LRECL=4096)
scp mf-target:'MYUSER.RACFDB.UNLOAD' ./racfunload.bin

# Step 2: convert to text (strip RDW)
python3 - <<'PY'
import struct
with open('racfunload.bin', 'rb') as f, open('racfunload.txt', 'w') as o:
    while True:
        rdw = f.read(4)
        if not rdw:
            break
        reclen = struct.unpack('>I', rdw)[0]
        rec = f.read(reclen - 4)
        o.write(rec.decode('cp1047', errors='replace') + '\n')
PY

# Step 3: extract users (record type 0201 in the IRRDBU00 layout)
grep '^0201' racfunload.txt | awk -F'|' '{print $2, $3}' | head
```

### Findings from a Parsed Unload

```text
// Once parsed, look for:
//   - SPECIAL/AUDITOR/OPERATIONS attribute holders (record 0201)
//   - UACC > READ on APF datasets (record 0401 / 0405)
//   - REVOKED users not deleted (record 0201)
//   - PASSDATE older than policy (record 0201)
//   - Dataset profiles with broad access list (record 0405)
```

---

## 15. SEAR API Usage

### What Is SEAR?

```text
// SEAR = Security Environment for Auditing RACF
// Open-source project from the Mainframe-Renewal-Project
// Provides a REST wrapper around native RACF services via z/OSMF
// Source: https://github.com/Mainframe-Renewal-Project/sear
```

### Deploy SEAR (Reference)

```bash
# On the target z/OS system (authorized only)
# 1. Clone the repo
git clone https://github.com/Mainframe-Renewal-Project/sear.git
cd sear
# 2. Follow README to build and deploy under z/OSMF
# 3. Configure RACF FACILITY class profiles (IRRSEAR.**)
# 4. Restart z/OSMF
```

### List Users via SEAR

```bash
# From the testing workstation (Kali)
export SEAR_USER=REPLACE_WITH_YOUR_RACF_USERID
export SEAR_PASS=REPLACE_WITH_YOUR_RACF_PASSWORD
export SEAR_HOST=REPLACE_WITH_YOUR_TARGET_HOST

# List every user
curl -k -u "$SEAR_USER:$SEAR_PASS" \
  "https://$SEAR_HOST/zosmf/api/rest/sear/users" \
  | jq '.users | length'

# Extract user IDs and attributes
curl -k -u "$SEAR_USER:$SEAR_PASS" \
  "https://$SEAR_HOST/zosmf/api/rest/sear/users" \
  | jq '.users[] | {name, attributes: .attributes}'
```

### Query a Dataset Profile

```bash
curl -k -u "$SEAR_USER:$SEAR_PASS" \
  "https://$SEAR_HOST/zosmf/api/rest/sear/datasets/SYS1.LINKLIB" \
  | jq '.'
```

### Query a Group

```bash
curl -k -u "$SEAR_USER:$SEAR_PASS" \
  "https://$SEAR_HOST/zosmf/api/rest/sear/groups/ADMGP" \
  | jq '.users[]'
```

### Enumerate APF via SEAR

```bash
# SEAR exposes the SETR-equivalent for the APF list
curl -k -u "$SEAR_USER:$SEAR_PASS" \
  "https://$SEAR_HOST/zosmf/api/rest/sear/apf" \
  | jq '.[]'
```

### Bulk Export

```bash
# Save full RACF dump via SEAR for offline analysis
curl -k -u "$SEAR_USER:$SEAR_PASS" \
  "https://$SEAR_HOST/zosmf/api/rest/sear/users" \
  > sear-users.json
curl -k -u "$SEAR_USER:$SEAR_PASS" \
  "https://$SEAR_HOST/zosmf/api/rest/sear/groups" \
  > sear-groups.json
curl -k -u "$SEAR_USER:$SEAR_PASS" \
  "https://$SEAR_HOST/zosmf/api/rest/sear/datasets" \
  > sear-datasets.json

# Combined size is typically a few MB for a medium-sized RACF
ls -lh sear-*.json
```

---

## 16. z/OSMF REST API

### Discover the z/OSMF Endpoint

```bash
export ZOSMF_USER=REPLACE_WITH_YOUR_USERID
export ZOSMF_PASS=REPLACE_WITH_YOUR_PASSWORD
export ZOSMF_HOST=REPLACE_WITH_YOUR_TARGET_HOST

# Test reachability
curl -k -u "$ZOSMF_USER:$ZOSMF_PASS" \
  "https://$ZOSMF_HOST/zosmf/rest/top/system/version"

# Discover available REST services
curl -k -u "$ZOSMF_USER:$ZOSMF_PASS" \
  "https://$ZOSMF_HOST/zosmf/api/rest/jobs" -i
```

### Jobs API

```bash
# List active jobs
curl -k -u "$ZOSMF_USER:$ZOSMF_PASS" \
  "https://$ZOSMF_HOST/zosmf/rest/jobs?owner=*&prefix=*&status=ACTIVE"

# Get job details
curl -k -u "$ZOSMF_USER:$ZOSMF_PASS" \
  "https://$ZOSMF_HOST/zosmf/rest/jobs/JOB12345"

# Fetch spool files
curl -k -u "$ZOSMF_USER:$ZOSMF_PASS" \
  "https://$ZOSMF_HOST/zosmf/rest/jobs/JOB12345/files"
```

### Files (Datasets) API

```bash
# List datasets matching a pattern
curl -k -u "$ZOSMF_USER:$ZOSMF_PASS" \
  "https://$ZOSMF_HOST/zosmf/rest/datasets?dslevel=SYS1.*"

# Read a dataset member
curl -k -u "$ZOSMF_USER:$ZOSMF_PASS" \
  -X GET \
  "https://$ZOSMF_HOST/zosmf/rest/datasets/SYS1.PARMLIB%28IEASYS00%29"
```

### Submit JCL via REST

```bash
# Submit JCL from the workstation
cat > submit.xml <<EOF
<?xml version="1.0"?>
<job xmlns="http://www.ibm.com/zosmf">
  <file>
//BENCHJOB JOB (ACCT),'BENCH',CLASS=A,MSGCLASS=X,NOTIFY=&SYSUID
//STEP01  EXEC PGM=IEBGENER
//SYSPRINT DD SYSOUT=*
//SYSIN    DD DUMMY
//SYSUT1   DD *
HELLO FROM AUTHORIZED ASSESSMENT
/*
//SYSUT2   DD SYSOUT=*
  </file>
</job>
EOF

curl -k -u "$ZOSMF_USER:$ZOSMF_PASS" \
  -H "Content-Type: application/json" \
  -X PUT \
  -d @submit.xml \
  "https://$ZOSMF_HOST/zosmf/rest/jobs"
```

### REST API Enumeration

```bash
# Some installations expose Swagger or API docs
curl -k -u "$ZOSMF_USER:$ZOSMF_PASS" \
  "https://$ZOSMF_HOST/zosmf/api/docs"

# Enumerate known REST endpoints
for path in jobs files datasets sysplex info sysdef metrics; do
  echo "=== $path ==="
  curl -k -u "$ZOSMF_USER:$ZOSMF_PASS" -s -o /dev/null -w "%{http_code}\n" \
    "https://$ZOSMF_HOST/zosmf/rest/$path"
done
```

---

## 17. Detection (Blue Side)

### SMF Records to Capture

```text
// Critical SMF record types for mainframe security monitoring
SMF type 30  -- Job/step start/end (who ran what, when)
SMF type 80  -- RACF authorization events (allow/deny)
SMF type 81  -- RACF command audit (ADDUSER, ALTUSER, etc.)
SMF type 83  -- Tape dataset access
SMF type 14/15 -- Dataset open/close (read/write)
SMF type 110 -- CICS transaction audit
SMF type 119 -- DB2 audit

// Ensure these are written to SMF dumps (SYS1.MAN1, MAN2, MAN3)
// and shipped to a SIEM (Splunk, QRadar, Elastic, Datadog, Chronicle)
```

### RACF Audit Configuration

```ts
// Enable RACF audit
SETROPTS AUDIT                      // general auditing on
SETROPTS SAUDIT                     // audit SPECIAL attribute use
SETROPTS CMDVIOL                    // audit command violations
SETROPTS OPERAUDIT                  // audit OPERATIONS attribute use
SETROPTS LOGOPTIONS                 // configure logging options

// Per-resource audit:
ALTDSD 'PROD.PAYROLL.**' AUDIT(ALL(READ(UPDATE(ALTER))))
//   Audits READ attempts to UPDATE, ALTER attempts to ALTER
```

### Forwarding SMF to SIEM

```bash
# Most SIEM vendors provide a mainframe SMF forwarder
# Common pattern: SMF -> IBM Common Data Provider -> Kafka/Syslog -> SIEM

# On the SIEM side, alert on:
#   - RACF command violations (SMF 80, return code indicating deny)
#   - ADDUSER/ALTUSER/DELUSER events outside change windows (SMF 81)
#   - SPECIAL attribute usage outside jump server IPs (SMF 80)
#   - Dataset opens of sensitive datasets from unexpected user IDs (SMF 14/15)
#   - TN3270 logon from non-corporate IP (SMF 80, terminal class)
```

### IBM Health Checker

```ts
// IBM Health Checker for z/OS runs checks against the security server
// In ISPF option 6:
HZSPRUN                           // run health checks now

// Review the latest check results
HZSVIEW                           // view health check output

// Key checks for security:
//   APF_CHECK              -- APF list integrity
//   RACF_PASSWORD_POLICY   -- password policy compliance
//   RACF_AUDIT_OPTIONS     -- audit option sanity
//   ICSF_KEY_LABELS        -- crypto key label hygiene
```

### z/OS Encryption Readiness Technology (zERT)

```text
// zERT discovers and reports TLS policy for z/OS TCP applications
// Useful for blue teams to identify unencrypted TN3270, FTP, and z/OSMF
// Output: SMF type 119 (DB2), 119 (TLS), and the zERT reporter
```

### Detecting the Techniques in This File

```text
// Map of technique to detection signal
LISTUSER *        -> SMF 81, RACF command audit; volume anomaly
SETR LIST         -> SMF 81; rare for non-SPECIAL users
IRRDBU00          -> SMF 81; only AUDITOR/SPECIAL should run it
APF write         -> SMF 14/15 to APF dataset + SMF 30 of the job
z/OSMF jobs API   -> z/OSMF SMF records; unusual client IP
SEAR API call     -> SMF 80 against IRRSEAR.* FACILITY profiles
```

---

## 18. Quick Reference Cheat Sheet

### Reach the Target

```bash
# Scan for TN3270
nmap -p 23,992,1027 --script=tn3270-info target.example.com

# Connect
c3270 target.example.com:23
c3270 -tls target.example.com:992

# Or via z/OSMF REST
curl -k -u "$ZOSMF_USER:$ZOSMF_PASS" \
  "https://$ZOSMF_HOST/zosmf/rest/top/system/version"
```

### Once on TSO

```ts
TIME                         // sanity check
WHO                          // who am I
ISPF                         // launch UI
LISTUSER *                   // dump every user
LISTGRP *                    // dump every group
SEARCH FILTER(*) CLIST(NAME) // filtered enumeration
SETR LIST                    // APF list and RACF options
LISTDSD DATASET('SYS1.**') ALL   // dataset profile detail
```

### RACF Quick Operations

```ts
LISTUSER IBMUSER             // single user detail
ALTUSER MYUSER REVOKE        // revoke
ALTUSER MYUSER PASSWORD(NEWPASS)
ADDUSER NEWUSER DFLTGRP(SYS1) PASSWORD(NEWPASS)
DELUSER NEWUSER
CONNECT USERID(U1) GROUP(G1) AUTHORITY(USE)
PERMIT 'DSN.**' CLASS(DATASET) ID(GRP1) ACCESS(READ)
ALTDSD 'DSN.**' UACC(NONE)
SETROPTS LIST
```

### Submit JCL

```ts
SUBMIT 'MY.JCL(MEMBER1)'
```

### JCL Skeleton for TSO Batch

```jcl
//JOBNAME  JOB (ACCT),'COMMENT',CLASS=A,MSGCLASS=X,NOTIFY=&SYSUID
//STEP01   EXEC PGM=IKJEFT01,DYNAMNBR=50
//SYSTSPRT DD SYSOUT=*
//SYSTSIN  DD *
LISTUSER *
/*
```

### JCL Skeleton for RACF Unload

```jcl
//IRRDBU00 JOB (ACCT),'RACF UNLOAD',CLASS=A,MSGCLASS=X
//STEP01   EXEC PGM=IRRDBU00,PARM=NOLOCKINPUT
//SYSPRINT DD SYSOUT=*
//INDD     DD DSN=SYS1.RACF.DB,DISP=SHR
//OUTDD    DD DSN=&HLQ..RACFDB.UNLOAD,
//            DISP=(NEW,CATLG),SPACE=(CYL,(50,50)),
//            DCB=(RECFM=VB,LRECL=4096,BLKSIZE=0)
```

### z/OSMF REST Quick Hits

```bash
# System version
curl -k -u "$U:$P" https://$H/zosmf/rest/top/system/version

# List jobs
curl -k -u "$U:$P" https://$H/zosmf/rest/jobs

# List datasets
curl -k -u "$U:$P" "https://$H/zosmf/rest/datasets?dslevel=SYS1.*"

# Submit JCL
curl -k -u "$U:$P" -H "Content-Type: application/json" \
  -d @job.json https://$H/zosmf/rest/jobs
```

### Find Special Users (Cheat)

```bash
# After IRRDBU00 unload, parsed:
grep '^0201' racfunload.txt | awk -F'|' '$0 ~ /SPECIAL|AUDITOR|OPR/ {print $2,$3}'
```

### Top Findings to Look For

```text
CRITICAL:
  - APF dataset writable by a non-operations user
  - SPECIAL user with dormant last-access
  - Hardcoded credentials in production JCL
  - IRRDBU00 unload file with broad read access

HIGH:
  - Dataset profile with UACC > READ on sensitive HLQ
  - CICS transaction with CMDPROT=NONE exposed externally
  - REVOKED users not deleted
  - DB2 PUBLIC grant on sensitive table

MEDIUM:
  - Out-of-window batch execution
  - TN3270 listener without TLS
  - z/OSMF REST reachable from broad IP range
  - RACF audit options disabled (SAUDIT/CMDVIOL/OPERAUDIT)

LOW:
  - Default TK4-/MVSCE credentials in a non-lab environment
  - JOB cards with REGION=0 or TIME=NOLIMIT
```

### Engagement Wrap-Up

```text
// Before signing off:
//   1. Document every finding with the LISTDSD/PERMIT/LISTUSER output
//   2. Map each finding to MITRE ATT&CK for Enterprise
//   3. Propose least-privilege remediation (ALTDSD/PERMIT/DELUSER)
//   4. Schedule a follow-up to verify remediation
//   5. Purge the IRRDBU00 unload from workstation and SIEM scratch
```
