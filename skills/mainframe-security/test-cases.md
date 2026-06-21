# Mainframe Security Test Cases

> This file is a companion to `SKILL.md`, providing structured test case templates for mainframe penetration testing scenarios.
> Purpose: Check each item during an authorized mainframe assessment to ensure no critical attack path is missed. Each case includes prerequisites, steps, expected results, and severity level.
> All tests are intended solely for authorized security assessments against lab or client-owned z/OS environments.

---

## Test Case Format

```
TC-MFXXX | [Category] Test Name
Severity: CRITICAL / HIGH / MEDIUM / LOW
Prerequisites: Conditions that must be met before testing
Test Steps: Specific operations
Expected Results: Observable behavior when the vulnerability exists
Remediation: Recommended defensive actions
Pass Criteria: How to verify the test succeeded
Reference Payload: Corresponding section in payloads.md
```

---

## Index

- [A. Lab and Session](#a-lab-and-session)
- [B. RACF Enumeration](#b-racf-enumeration)
- [C. Dataset and APF](#c-dataset-and-apf)
- [D. Subsystems](#d-subsystems)
- [E. Programmatic Access](#e-programmatic-access)

---

## A. Lab and Session

### TC-MF001 | Hercules Emulator with TK4-/MVSCE Bring-Up

- **Severity**: LOW
- **Objective**: Bring up a working IBM mainframe lab on commodity hardware using the Hercules emulator and the freely available TK4- (or MVSCE) MVS 3.8j distribution, so subsequent test cases can run against a known-good target.
- **Prerequisites**:
  - Linux or macOS host with at least 4 GB RAM and 10 GB free disk
  - Hercules emulator built or installed (`/opt/hercules/bin/hercules`)
  - TK4- or MVSCE distribution archive downloaded from the Open Mainframe Project or its community mirror
  - A TN3270 client (`x3270`, `c3270`, or `wc3270`) installed
- **Test Steps**:
  1. Verify the Hercules binary is on PATH: `hercules --version`
  2. Unpack TK4- into `~/mf-lab/tk4-` and review `README.md` for the current default ports and credentials
  3. Start Hercules with the TK4- configuration: `cd ~/mf-lab/tk4- && ./mvs`
  4. Watch the Hercules console for `MVS INIT` messages and the message indicating the system has entered a wait state ready for logons
  5. From a second terminal, attach a TN3270 client: `c3270 localhost:3270` (or the port documented in the distribution)
  6. At the VTAM logon panel, enter `LOGON` followed by the distribution-provided default user ID
- **Expected Result**: Hercules reaches a stable MVS wait state, the TN3270 client renders a recognizable VTAM/TSO logon panel, and the default user ID authenticates successfully, delivering the operator to the TSO READY prompt.
- **Remediation**: N/A (lab bring-up). If startup fails, check Hercules build (`./util/bldcnf.pl`, `make`), verify disk images unpacked, and confirm the configured port is not in use.
- **Pass Criteria**: A TSO READY prompt is reachable through the TN3270 session; `TIME` and `PROFILE` commands return valid output.
- **Mitre**: N/A
- **Difficulty**: 2 (intermediate)
- **Tags**: [lab, hercules, tk4, emulator, setup]
- **Reference**: payloads.md Section 2 -- Lab Setup

---

### TC-MF002 | TN3270 Connection and Logon

- **Severity**: MEDIUM
- **Objective**: Validate the ability to connect to a TN3270 listener, negotiate the terminal type, and obtain an interactive TSO session against the target mainframe.
- **Prerequisites**:
  - Network reachability to the TN3270 listener (typically TCP 23 or 992, occasionally 1027)
  - Valid or default TSO user ID and current password (for lab: the TK4-/MVSCE default)
  - `x3270` or `c3270` client installed
- **Test Steps**:
  1. Probe the listener with `nmap -sV -p 23,992,1027 --script=tn3270-info <target>`
  2. Open a session: `c3270 <target>:<port>`
  3. At the logon panel, enter `LOGON` and supply the user ID
  4. Enter the current password when prompted; press Enter to submit
  5. Confirm that the TSO READY prompt appears and that `PROFILE` returns sensible terminal attributes
- **Expected Result**: The TN3270 negotiation completes (typically TN3270E with device type 3278-2 or 3279-2), the user ID authenticates, and the operator lands at the TSO READY prompt with the screen width/height reported correctly by `PROFILE`.
- **Remediation**: Disable the TN3270 listener on production external interfaces; require TN3270E over TLS (port 992); restrict logon by source IP via VTAM APPL definition.
- **Pass Criteria**: A successful logon yields a READY prompt; `WHO` or `LISTUSER <myid>` returns the current user identity.
- **Mitre**: T1078-Valid Accounts
- **Difficulty**: 2
- **Tags**: [tn3270, logon, vtam, session]
- **Reference**: payloads.md Section 3 -- TN3270 Connection

---

### TC-MF003 | TSO and ISPF Navigation

- **Severity**: LOW
- **Objective**: Verify the operator can navigate TSO and the ISPF Primary Option Menu, which is a precondition for every subsequent test case.
- **Prerequisites**:
  - A working TSO session (TC-MF002)
  - ISPF available on the target (standard on z/OS and on TK4-/MVSCE)
- **Test Steps**:
  1. At the READY prompt, enter `ISPF` to launch the Primary Option Menu
  2. Browse to option `1` (View) or `2` (Edit) and open a sample dataset (e.g., `IBMUSER.CLIST`)
  3. Return to the Primary Option Menu and open option `3.4` (Datasets List) to list datasets by pattern
  4. Open option `6` (Command) and execute a TSO command interactively (e.g., `TIME`)
  5. Use `=x` to exit ISPF cleanly back to READY
- **Expected Result**: ISPF renders the familiar Primary Option Menu, dataset browsing and editing work, the DSLIST panel returns results for a wildcard pattern, and the command panel executes TSO commands.
- **Remediation**: N/A on lab. On production, restrict ISPF access where the user's role does not require it, and prefer the z/OSMF REST API for routine operator tasks to reduce interactive shell exposure.
- **Pass Criteria**: Each of the five steps completes without error; no 878-10 abends or storage shortages.
- **Mitre**: T1078-Valid Accounts
- **Difficulty**: 1 (novice)
- **Tags**: [tso, ispf, navigation]
- **Reference**: payloads.md Section 4 -- TSO/ISPF Navigation

---

## B. RACF Enumeration

### TC-MF004 | RACF LISTUSER and LISTGRP Enumeration

- **Severity**: HIGH
- **Objective**: Enumerate the RACF user and group directory, identify SPECIAL/AUDITOR/OPERATIONS attribute holders, and flag dormant or revoked-but-not-deleted accounts.
- **Prerequisites**:
  - Authenticated TSO session with permission to run RACF LISTUSER/LISTGRP (typically any user)
  - An output dataset or screen-capture facility to record the dump
- **Test Steps**:
  1. At READY, run `LISTUSER *` and capture the output
  2. Filter for attribute holders by running `SEARCH FILTER(*) CLIST(NAME)` and grepping for SPECIAL, AUDITOR, OPERATIONS in the captured output
  3. Run `LISTGRP *` and capture group definitions and their connected users
  4. Identify REVOKED users (still present) and users with PASSDATE older than the corporate password policy
  5. Cross-reference SPECIAL/AUDITOR/OPERATIONS holders against expected role rosters
- **Expected Result**: A complete user and group directory is captured; at least one finding is documented for the test report (typically dormant SPECIAL users, revoked users not deleted, or users with stale PASSDATE).
- **Remediation**: Delete REVOKED users; strip attributes from non-essential accounts; implement just-in-time elevation; enforce password rotation within policy; audit group ownership chains.
- **Pass Criteria**: The captured dump includes every active user, at least one attribute holder is identified, and a finding (or a documented clean baseline) is produced.
- **Mitre**: T1087-Account Discovery, T1078-Valid Accounts
- **Difficulty**: 3
- **Tags**: [racf, listuser, listgrp, enum, special]
- **Reference**: payloads.md Sections 5 and 6 -- RACF Fundamentals and Command Reference

---

### TC-MF005 | APF Library Audit

- **Severity**: CRITICAL
- **Objective**: Enumerate Authorized Program Facility (APF) libraries, identify any backed by user-writable datasets, and document the escalation primitive that a write to such a library would grant.
- **Prerequisites**:
  - Authenticated TSO session with permission to run `SETR LIST` (most users)
  - RACF READ access to each APF dataset's profile
  - Knowledge of the current LPAR's PROGxx member location for cross-reference
- **Test Steps**:
  1. At READY, run `SETR LIST` to dump the current APF list (system and dynamic)
  2. For each APF dataset, run `LISTDSD DATASET('<dsn>') ALL` and record UACC and access list
  3. Identify APF datasets where UACC is greater than READ, or where a broad group has UPDATE/ALTER
  4. Cross-reference dynamic APF entries against the PROGxx member to confirm they are intentional
  5. (Lab only) Demonstrate planting a tiny authorized program in a writable APF dataset; on client work, stop at documentation
- **Expected Result**: At least one APF dataset is identified where UACC is broader than READ or a non-operations group holds UPDATE/ALTER. If none are found, the audit produces a clean baseline that can be compared at the next assessment.
- **Remediation**: Set UACC=READ on every APF dataset; remove UPDATE/ALTER from non-operations groups; restrict PROGxx changes to controlled change windows; enable IBM Health Checker `APF_CHECK` and remediate findings.
- **Pass Criteria**: Every APF dataset has a recorded UACC and access list; every broad-access entry is documented; the audit produces either a finding or a signed-off clean baseline.
- **Mitre**: T1068-Exploitation for Privilege Escalation, T1574-Hijack Execution Flow
- **Difficulty**: 4
- **Tags**: [apf, authorized, library, escalate]
- **Reference**: payloads.md Section 7 -- APF Library Audit

---

### TC-MF006 | Dataset Access Control Testing

- **Severity**: HIGH
- **Objective**: Enumerate sensitive dataset profiles, test READ/UPDATE/ALTER/CONTROL access rules, and identify over-permissive UACC settings or access list entries.
- **Prerequisites**:
  - Authenticated TSO session
  - A target dataset pattern set (typically `SYS1.**`, `PROD.**`, `PAYROLL.**`, `HLQ.**`)
  - RACF READ access to the DATASET class resource profiles
- **Test Steps**:
  1. At READY, run `SEARCH CLASS(DATASET) FILTER(SYS1.**)` to enumerate matching profiles
  2. For each profile, run `LISTDSD DATASET('<dsn>') ALL` and record UACC, access list, and warning conditions
  3. Attempt READ access to a sampled sensitive dataset via `ALLOC` then `BROWSE` to confirm the access list
  4. Flag profiles where UACC is READ/UPDATE/ALTER when it should be NONE
  5. Flag profiles where a broad group has UPDATE/ALTER without business justification
- **Expected Result**: A dataset access matrix is produced; at least one over-permissive profile is documented (or a clean baseline signed off). READ attempts to datasets that the access list should deny return ICH408I.
- **Remediation**: `ALTDSD DATASET('<dsn>') UACC(NONE)`; `PERMIT '<dsn>' CLASS(DATASET) ID(<group>) ACCESS(NONE)`; periodically dump and diff the dataset access matrix.
- **Pass Criteria**: Every sensitive dataset profile has UACC and access list recorded; findings are documented with the offending `PERMIT` entries.
- **Mitre**: T1003-OS Credential Dumping, T1083-File and Directory Discovery
- **Difficulty**: 3
- **Tags**: [dataset, listcat, listdsn, permit, uacc]
- **Reference**: payloads.md Section 8 -- Dataset Access Control

---

## C. Dataset and APF (JCL/Batch)

### TC-MF007 | JCL Submission and JOB Card Review

- **Severity**: MEDIUM
- **Objective**: Validate the ability to submit JCL from a TSO session, review JOB cards for credential handling, and detect jobs whose class or USER= permit execution outside intended windows.
- **Prerequisites**:
  - Authenticated TSO session with JOB submission privilege
  - An output class and message class assigned by the installation
  - SDSF or equivalent output browser (option `O` or `ST` in ISPF)
- **Test Steps**:
  1. Author a benign JCL member that performs `IEBGENER` to copy a dataset to the spool
  2. Review the JOB card for hardcoded `USER=`/`PASSWORD=` strings or missing `MSGCLASS`/`CLASS`
  3. Submit the job from ISPF option `3.4` (`SUBMIT`) or from READY (`SUBMIT '<dsn>(member)'`)
  4. Open SDSF and navigate to the output class to confirm the job executed
  5. Inspect the JES2 job log for step completion and any security-related messages
- **Expected Result**: The submitted JCL executes and produces the expected output on the spool. JOB card review produces either a finding (hardcoded credentials, wrong class, missing accounting info) or a documented clean baseline.
- **Remediation**: Remove hardcoded credentials from JCL; require RACF surrogate (`SURROGAT` class) for cross-user submission; restrict JOB CLASS to role-appropriate values; run scheduled audits of production JCL libraries for `PASSWORD=` strings.
- **Pass Criteria**: The job executes; the JOB card is documented; any finding is remediated or accepted with risk owner sign-off.
- **Mitre**: T1053-Scheduled Task/Job, T1078-Valid Accounts
- **Difficulty**: 3
- **Tags**: [jcl, submit, jes2, job-card]
- **Reference**: payloads.md Section 9 -- JCL Submission

---

## D. Subsystems

### TC-MF008 | CICS Transaction Discovery

- **Severity**: HIGH
- **Objective**: Enumerate CICS transaction codes via CEDA, identify unsigned or overridden transactions, and assess CICS Web Services exposure.
- **Prerequisites**:
  - Authenticated CICS session (`CESN`) or CICS Explorer with operator privileges
  - READ access to the CICS system definition datasets (CSD)
- **Test Steps**:
  1. From a CICS terminal, invoke `CEDA VIEW GROUP(*)` (or `CEDA LIST TRANID(*)`)
  2. Filter for transaction IDs with `TASKREQ=NO`, `ROUTING=YES`, or `CMDPROT=NONE` (potential findings)
  3. Open CICS Explorer and review Web Services bindings for unsigned service handlers
  4. Cross-reference transactions with RACF `TERMINAL` or `TICS` class profiles where applicable
  5. Document findings: unsigned transactions, missing RACF TICS protection, or web service bindings exposing internal programs
- **Expected Result**: A transaction inventory is produced; at least one transaction is flagged for follow-up (or a clean baseline is documented).
- **Remediation**: Apply `CMDPROT=ALL` to user-facing transactions; protect CICS resources via the `TICS` and `TRANSACTION` classes; disable unsigned CICS Web Services handlers; periodic CEDA diff.
- **Pass Criteria**: Every transaction in the scope has an entry in the inventory; every flagged item is documented with remediation guidance.
- **Mitre**: T1120-Peripheral Device Discovery, T1068-Exploitation for Privilege Escalation
- **Difficulty**: 4
- **Tags**: [cics, ceda, transaction, web-services]
- **Reference**: payloads.md Section 10 -- CICS Transaction Testing

---

### TC-MF009 | DB2 for z/OS SPUFI Query

- **Severity**: MEDIUM
- **Objective**: Validate the ability to execute SQL against DB2 for z/OS via SPUFI, enumerate DB2 plan/package security, and flag over-permissive grants.
- **Prerequisites**:
  - DB2I menu access from TSO (SPUFI option)
  - A valid DB2 primary authorization ID with SELECT on the target table
  - Knowledge of the target subsystem identifier (SSID)
- **Test Steps**:
  1. From TSO, enter `SPUFI` and configure the DB2 SSID and input/output datasets
  2. Author a benign `SELECT CURRENT SQLID, CURRENT SERVER FROM SYSIBM.SYSDUMMY1;` and execute
  3. Enumerate grants with `SELECT GRANTEE, NAME, OWNER FROM SYSIBM.SYSTABAUTH WHERE TCREATOR='SYSIBM';`
  4. Flag grants to PUBLIC on sensitive tables; flag plans/packages with invalid owners
  5. Document findings with the offending GRANT statements
- **Expected Result**: SPUFI returns rows for the SYSIBM catalog queries; at least one finding is produced (PUBLIC grant, stale plan owner, or invalid package) or a clean baseline is documented.
- **Remediation**: `REVOKE SELECT ON <table> FROM PUBLIC;` for sensitive tables; review plan/package ownership periodically; tighten DB2 primary auth ID mapping via RACF group-to-auth-ID translation.
- **Pass Criteria**: The SYSIBM catalog queries return rows; findings (if any) are documented with the offending GRANT statements.
- **Mitre**: T1213-Data from Information Repositories, T1003-OS Credential Dumping
- **Difficulty**: 3
- **Tags**: [db2, spufi, plan, package, grant]
- **Reference**: payloads.md Section 11 -- DB2 for z/OS

---

### TC-MF010 | JES2 Job Enumeration

- **Severity**: MEDIUM
- **Objective**: Enumerate active and completed JES2 jobs, identify jobs executing with privileged USER=, and detect jobs outside expected time windows.
- **Prerequisites**:
  - Authenticated TSO session with SDSF access
  - READ access to the OUTPUT and STATUS SDSF queues
- **Test Steps**:
  1. From ISPF, open SDSF (`=M.5` or `SDSF` at READY)
  2. In the `ST` (status) queue, use `FILTER JOBID EQ J*` and `OWNER *` to enumerate
  3. Open the `DA` (display active) queue to capture executing jobs
  4. For each interesting job, examine the JOB card `USER=` and accounting fields
  5. Cross-reference job execution times against expected windows (job running at 03:00 outside maintenance?)
- **Expected Result**: An inventory of active and recent jobs is captured; at least one finding (privileged USER=, out-of-window execution, or unexpected job class) is documented.
- **Remediation**: Enforce job class and reader-time restrictions; audit `USER=` override usage; require JES2 security labels (SECLABEL class) for privileged batch.
- **Pass Criteria**: The SDSF queues are browsable; the job inventory contains at least the in-scope LPARs' active jobs; findings are documented.
- **Mitre**: T1053-Scheduled Task/Job, T1087-Account Discovery
- **Difficulty**: 3
- **Tags**: [jes2, sdsf, jobs, enumeration]
- **Reference**: payloads.md Section 13 -- JES2/JES3 Job Submission

---

## E. Programmatic Access

### TC-MF011 | RACF IRRDBU00 Database Unload

- **Severity**: CRITICAL
- **Objective**: Use the IRRDBU00 utility to unload the RACF database to a sequential file for offline analysis, producing a portable baseline that supports comprehensive access-control review.
- **Prerequisites**:
  - Authenticated TSO session with READ access to `SYS1.SAMPLIB(IRRDBU00)` and authority to submit IRRDBU00 JCL (typically AUDITOR attribute or equivalent)
  - Output dataset pre-allocated with appropriate DCB (LRECL=4096, RECFM=VB)
- **Test Steps**:
  1. Allocate the output dataset: `ALLOC DD(IRROUT) DA('<hlq>.RACFDB.UNLOAD') NEW ...`
  2. Author JCL that executes `PGM=IRRDBU00` with `SYSIN DD *` specifying the unload options
  3. Submit the job and review the JES2 output for `IRRDBU00 COMPLETED`
  4. Download the unload file to a workstation and parse with the SEAR toolkit or a custom Python parser
  5. Produce a findings report focusing on the highest-leverage patterns (broad UACC, APF list, SPECIAL holders, REVOKED users)
- **Expected Result**: The IRRDBU00 job completes with condition code 0; the unload file contains structured records for every user, group, and dataset profile; the parsed report identifies the agreed-upon findings.
- **Remediation**: Treat the IRRDBU00 unload as sensitive; protect it with RACF encryption; rotate the dataset periodically; ensure only AUDITOR-class users can submit IRRDBU00 jobs.
- **Pass Criteria**: The job produces a non-empty unload file; the offline parse yields a structured report; findings are communicated to the system owner.
- **Mitre**: T1003-OS Credential Dumping, T1552-Unsecured Credentials
- **Difficulty**: 4
- **Tags**: [irrdbu00, racf, unload, baseline]
- **Reference**: payloads.md Section 14 -- RACF Database Extraction

---

### TC-MF012 | SEAR API Call for Programmatic RACF Testing

- **Severity**: MEDIUM
- **Objective**: Validate the ability to use the SEAR (Security Environment for Auditing RACF) REST API for programmatic enumeration and testing of RACF objects.
- **Prerequisites**:
  - SEAR deployed on the target z/OS or zPDT system, exposed via z/OSMF
  - Valid RACF credentials with permission to invoke SEAR endpoints
  - `curl` and `jq` on the testing workstation
- **Test Steps**:
  1. Verify z/OSMF reachability: `curl -k -u "$SEAR_USER:$SEAR_PASS" https://<host>/zosmf/rest/top/system/version`
  2. List users via SEAR: `curl -k -u "$SEAR_USER:$SEAR_PASS" https://<host>/zosmf/api/rest/sear/users | jq '.users | length'`
  3. Query a specific dataset profile: `curl -k -u "$SEAR_USER:$SEAR_PASS" https://<host>/zosmf/api/rest/sear/datasets/SYS1.LINKLIB`
  4. Query a specific group: `curl -k -u "$SEAR_USER:$SEAR_PASS" https://<host>/zosmf/api/rest/sear/groups/ADMGP`
  5. Document findings and the corresponding REST endpoint sequence for the client report
- **Expected Result**: SEAR responds with structured JSON for each endpoint; the user/dataset/group queries return data consistent with the `LISTUSER` / `LISTDSD` / `LISTGRP` output gathered in earlier cases.
- **Remediation**: Protect SEAR endpoints with RACF `FACILITY` class profiles (e.g., `IRRSEAR.**`); require TLS for all z/OSMF REST traffic; audit SEAR calls via SMF type 80/81.
- **Pass Criteria**: At least one user-list, one dataset-profile, and one group query complete successfully; the JSON payloads are parseable.
- **Mitre**: T1213-Data from Information Repositories, T1078-Valid Accounts
- **Difficulty**: 3
- **Tags**: [sear, rest, zosmf, api]
- **Reference**: payloads.md Section 15 -- SEAR API Usage
