# Lab-Driven Walkthrough: End-to-End Mainframe Assessment

## Overview

This walkthrough is the practice companion to `mainframe-security-playbook.md`. Where the playbook describes methodology and `quick-reference-card.md` lists commands, this guide takes a single target from zero to findings and narrates every step in between. It is designed for a practitioner who has just finished building the Hercules + TK4- lab and wants to rehearse a full engagement sequence before touching client infrastructure.

The walkthrough covers six exercises. Each exercise has a learning objective, a list of prerequisites, a step-by-step narrative with the commands issued and the expected output, a verification checklist, and a "what to write in your report" block. The exercises are sequential: each one assumes the previous exercise's findings are in hand. A practitioner who completes all six is ready to execute a real engagement under supervision.

The walkthrough is lab-only. None of the techniques here should be executed against production mainframes without explicit written authorization. The lab target is a free, community-supported distribution; production mainframes have monitoring, change control, and operators who will notice.

## Objective

After completing the six exercises in this walkthrough, the practitioner should be able to:

1. Build, verify, and reset a Hercules + TK4- mainframe lab.
2. Reach the TN3270 listener, log on to TSO, navigate ISPF, and pivot to CICS.
3. Enumerate RACF users, groups, attributes, and identify dormant accounts.
4. Audit APF libraries and demonstrate an authorized-program attack in the lab.
5. Capture an IRRDBU00 unload and analyze it offline for privilege-escalation paths.
6. Write a one-page engagement report that a mainframe-naive reader can act on.

## Exercise 1: Build and Verify the Lab

### Learning objective

Stand up a working mainframe lab that subsequent exercises depend on. Verify each layer of the stack (Hercules, MVS, VTAM, TSO, ISPF).

### Prerequisites

- A Linux host (Debian/Ubuntu recommended) with at least 4 GB RAM and 20 GB free disk.
- Root or sudo for package installation.
- A second terminal for the TN3270 client.

### Step-by-step

```bash
# Step 1: Install build prerequisites
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev flex bison \
  git autoconf automake libtool pkg-config zlib1g-dev c3270

# Step 2: Clone and build SDL-Hercules-390 (Hyperion)
git clone --depth=1 https://github.com/SDL-Hercules-390/hyperion.git
cd hyperion
./util/bldcnf.pl
./configure --prefix=/opt/hercules
make -j"$(nproc)"
sudo make install
cd ..

# Step 3: Fetch TK4-
git clone --depth=1 https://github.com/MVS-SOW/tk4-.git
cd tk4-
less README.md   # Read the README; default user IDs and ports are documented here

# Step 4: Start Hercules + TK4-
./mvs

# Step 5 (in a second terminal): Connect with c3270
c3270 localhost:3270
```

### Expected output

At step 4, the Hercules console should print boot messages and end in a wait state ready for logons. At step 5, c3270 should connect and render the VTAM logon panel.

### Verification checklist

```text
[ ] Hercules console shows "MVS380X READY" or similar wait state
[ ] c3270 connects to localhost:3270 and renders the VTAM logon panel
[ ] The default user (per README) authenticates and reaches TSO READY
[ ] ISPF launches (option ISPF from READY)
[ ] LISTUSER * returns sample users
[ ] JES2 is reachable via SDSF (ISPF option =M.5)
```

### What to write in your report

Nothing yet. This is a lab setup exercise. Note the build time and any deviations from the README for future reference.

## Exercise 2: Reach TSO and Navigate to CICS

### Learning objective

Acquire an interactive session on the lab mainframe, navigate from TSO to ISPF, and pivot to a CICS region. This exercises the surface that a real engagement would touch.

### Prerequisites

- Exercise 1 complete. Lab running and reachable.

### Step-by-step

```text
1. From c3270, at the VTAM logon panel, enter:
   LOGON IBMUSER
   (Password per README; for TK4- the default is typically SYS1 or documented in README.)

2. At TSO READY prompt, verify identity:
   LISTUSER IBMUSER

3. Launch ISPF:
   ISPF

4. From ISPF Primary Option Menu, navigate:
   =M.5      -> SDSF
   DA        -> Display Active users
   Verify the IBMUSER session appears.

5. Exit SDSF (=X), return to ISPF Primary Option Menu.

6. From TSO READY (exit ISPF via =X then =X again):
   CICS
   (Or the CICS region-specific transaction, per TK4- README.)
```

### Expected output

At step 2, `LISTUSER IBMUSER` prints the user's attributes, default group, and PASSDATE. At step 3, ISPF displays the Primary Option Menu. At step 6, CICS displays the welcome panel.

### Verification checklist

```text
[ ] LISTUSER returns valid output (USER=IBMUSER, attributes)
[ ] ISPF Primary Option Menu renders correctly
[ ] SDSF shows the IBMUSER address space as active
[ ] CICS region is reachable and accepts a transaction
```

### What to write in your report

Document the path from network reach to CICS. In a client engagement, this becomes the "attack surface summary" section.

## Exercise 3: Enumerate RACF Users and Find Dormant Accounts

### Learning objective

Map the identity landscape. Identify users with SPECIAL, AUDITOR, or OPERATIONS attributes. Find REVOKED-but-not-DELETED users and dormant accounts.

### Prerequisites

- Exercises 1 and 2 complete. Logged into TSO as a user with enough privilege to run LISTUSER.

### Step-by-step

```ts
// Dump every user
LISTUSER *

// Dump every group
LISTGRP *

// Find SPECIAL users (grep the LISTUSER output)
// In the lab, scan output for "ATTRIBUTES = SPECIAL"

// Find REVOKED users (grep for "REVOKE")
// These users are disabled but not deleted.

// Find dormant accounts by PASSDATE
// PASSDATE is shown in LISTUSER; a user whose PASSDATE is older than
// 90 days is a candidate for dormancy.
```

### Expected output

LISTUSER produces a multi-line block per user. Capture the output to a dataset for offline analysis.

### Verification checklist

```text
[ ] LISTUSER * completes without errors
[ ] Output captured to a dataset (XMIT to workstation if needed)
[ ] SPECIAL users identified and listed
[ ] REVOKED users identified (counted)
[ ] Dormant accounts identified (PASSDATE > 90 days old)
```

### What to write in your report

For each SPECIAL user, list the user ID, the owning group, and the last PASSDATE. For each dormant account, propose either revalidation or deletion. The report's "Identity Hygiene" section is built from this exercise.

## Exercise 4: Audit APF Libraries

### Learning objective

Identify APF-authorized libraries, check whether any are backed by user-writable datasets, and (in the lab only) demonstrate the impact of planting an authorized program.

### Prerequisites

- Exercise 3 complete. User has enough privilege to run SETR LIST and LISTDSD.

### Step-by-step

```ts
// Dump the APF list
SETR LIST

// For each APF library dataset, examine access:
LISTDSD DATASET('SYS1.LINKLIB') ALL
LISTDSD DATASET('SYS1.SVCLIB') ALL

// If the lab has a user-writable APF dataset (some TK4- builds do):
LISTDSD DATASET('USER.LINKLIB') ALL

// Cross-reference against PROGxx:
// In ISPF option 2 (EDIT), browse SYS1.PARMLIB(PROGAA)
// (or whichever PROGxx member the LPAR loads from)
// Look for APF ADD statements.

// In the lab ONLY, demonstrate planting an authorized program:
// 1. Write a small assembler program that calls SVC 34 (something innocuous).
// 2. Link-edit with AC(1) into a user-writable APF library.
// 3. CALL the program from TSO. Verify authorized execution.
```

### Expected output

`SETR LIST` shows the active APF list. `LISTDSD` shows UACC and access list per dataset. Any APF dataset with UACC > READ or with a broad UPDATE/ALTER group is a finding.

### Verification checklist

```text
[ ] SETR LIST output captured
[ ] Each APF dataset's UACC and access list recorded
[ ] User-writable APF datasets flagged
[ ] PROGxx member reviewed for dynamic APF additions
[ ] (Lab only) Authorized-program execution demonstrated
```

### What to write in your report

For each user-writable APF dataset, document the dataset name, the user-writable entry (group or user ID), and the access level (UPDATE or ALTER). Propose the fix: change UACC to READ, scope the access list, or remove the dataset from APF.

## Exercise 5: Capture and Analyze an IRRDBU00 Unload

### Learning objective

Capture the RACF database to a sequential file using IRRDBU00, transfer it to the workstation, and analyze it offline for privilege-escalation paths.

### Prerequisites

- Exercise 4 complete. User has authority to submit IRRDBU00 jobs.

### Step-by-step

```jcl
//IRRDBU00 JOB (ACCT),'IRRDBU',CLASS=A,MSGCLASS=A
//STEP1   EXEC PGM=IRRDBU00,PARM='NOLOCK'
//SYSPRINT DD SYSOUT=*
//OUTDD    DD DSN=&&RACFDBU,DISP=(NEW,PASS),
//            SPACE=(CYL,(50,50),RLSE),
//            DCB=(RECFM=VB,LRECL=4096,BLKSIZE=0)
//SYSIN    DD *
NOLOCK
/*
//*
// Step 2: Download OUTDD via IND$FILE (or FTP)
// At TSO READY:
//  IND$FILE PUT 'MYUSER.RACFDBU' (from ISPF option 6)
// Or via FTP from the workstation:
//  ftp lab-host
//  > get 'MYUSER.RACFDBU' racfdbu.txt
```

Once on the workstation:

```bash
# Inspect the first few records
head -50 racfdbu.txt

# Count records per type (user records, group records, dataset profiles)
awk -F'|' '{print $1}' racfdbu.txt | sort | uniq -c | sort -rn | head -20

# Find users with SPECIAL attribute
grep -E 'USER.*SPECIAL' racfdbu.txt | head -20

# Find datasets with UACC > READ
grep -E 'DATASET.*UACC' racfdbu.txt | grep -E 'UACC=(UPDATE|ALTER|CONTROL)' | head -20
```

### Expected output

IRRDBU00 produces a sequential file with one record per RACF object. Offline analysis surfaces patterns that on-LPAR review misses.

### Verification checklist

```text
[ ] IRRDBU00 job completed with return code 0
[ ] Output dataset downloaded to workstation
[ ] Record-type counts produced
[ ] SPECIAL users identified offline
[ ] Over-permissive dataset profiles identified offline
```

### What to write in your report

Cross-reference the offline analysis with the on-LPAR findings from Exercise 3 and 4. The IRRDBU00 analysis often surfaces findings that on-LPAR review missed because the user's on-LPAR session could not see them.

## Exercise 6: Write the One-Page Engagement Report

### Learning objective

Convert the findings from Exercises 3-5 into a one-page engagement report that a mainframe-naive reader (e.g., a CISO) can act on.

### Prerequisites

- Exercises 3, 4, and 5 complete. Findings documented.

### Step-by-step

```text
1. Open a blank document with the engagement header:
   - Engagement name and date
   - Target LPAR and HLQs in scope
   - Tester name and credentials used
   - Authorization reference (RoE citation)

2. Write the executive summary (3-4 sentences):
   - What was assessed
   - Headline finding
   - Overall posture

3. Write the findings table:
   | ID | Title | Severity | Affected | Recommendation |
   |----|-------|----------|----------|----------------|
   | F1 | User-writable APF library | CRITICAL | USER.LINKLIB | Remove from APF; restore from backup |
   | F2 | Dormant IBMUSER | HIGH | IBMUSER | Delete or revalidate |
   | F3 | Over-permissive UACC on PAYROLL.* | HIGH | PAYROLL.* | UACC=NONE; scoped access list |
   | ... | ... | ... | ... | ... |

4. Write the body of the report:
   - For each finding, one paragraph of context
   - The LISTUSER/LISTDSD/SETR LIST snippet that demonstrates the finding
   - The proposed remediation command (ALTDSD, PERMIT, DELUSER, etc.)
   - The blast radius (number of users/datasets affected)

5. Close with next steps:
   - Re-test window
   - Suggested follow-up areas (z/OSMF, CICS, DB2)
   - Contact information

6. Review with a mainframe-naive peer. If they cannot understand the report, rewrite.
```

### Expected output

A one-page report that a CISO can read in 5 minutes and act on.

### Verification checklist

```text
[ ] Report fits on one page
[ ] Executive summary is 3-4 sentences
[ ] Findings table is complete
[ ] Each finding has a remediation command
[ ] A mainframe-naive peer has reviewed and understood
```

### What to write in your report

This exercise produces the report itself. There is nothing further to write.

## Closing Notes

These six exercises cover the core sequence of a mainframe engagement. Real engagements are messier: the LPAR may not have a CICS region, the user IDs may not include IBMUSER, the APF list may be gold-plated already. The exercises teach the sequence; the playbook and reference card teach the variation.

After completing the walkthrough, the practitioner should:

1. Repeat the exercises against MVSCE to learn the variations across distributions.
2. Read the Kaspersky Securelist RACF deep dives (cited in the playbook).
3. Join the DEF CON mainframe village Discord for community support.
4. Set up a recurring lab-refresh cadence (quarterly) to track upstream changes.

The next guide in this directory, `real-world-incident-case-studies.md`, provides the historical context for the patterns this walkthrough exercises. The `quick-reference-card.md` is the operator's cheatsheet during live work.

## References

- Kaspersky Securelist: "Approach to mainframe security" (search Securelist for "RACF").
- Kaspersky Securelist: "Deconstructing RACF".
- IBM Redbooks: "z/OS Security Server RACF Security Administrator's Guide".
- mainframed/Enumeration: https://github.com/mainframed/Enumeration.
- Mainframe-Renewal-Project/SEAR: https://github.com/Mainframe-Renewal-Project/sear.
- SDL-Hercules-390/hyperion: https://github.com/SDL-Hercules-390/hyperion.
- MVS-SOW/tk4-: https://github.com/MVS-SOW/tk4-.
- MVS-SOW/MVSCE: https://github.com/MVS-SOW/MVSCE.
- DEF CON mainframe village (annual venue).
- Open Mainframe Project (Linux Foundation).
