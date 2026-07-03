# Mainframe Security Quick Reference Card

## Overview

This is the operator cheatsheet for mainframe security work on authorized engagements. It distills the most-used commands, attack surfaces, and response steps into a single page-flip reference. It assumes the reader has worked through `mainframe-security-playbook.md` and `payloads.md` and just wants the one-liners at their fingertips during a session.

Sections are organized by what the operator is trying to do, not by subsystem. If you are doing recon, flip to "Recon One-Liners." If you are auditing RACF, flip to "RACF Command Matrix." If you are responding to a suspected compromise, flip to the "Response Playbook" at the end and follow it step by step.

The card assumes RACF as the security server. ACF2 and Top Secret equivalents are noted where they differ materially. Code blocks are valid for z/OS V2R5 and later; consult the IBM Knowledge Center for version-specific differences.

## Objective

Provide a one-page-flip reference that an operator can keep open in a second terminal during mainframe security work, covering:

1. Security server command matrices (RACF, ACF2, Top Secret).
2. Recon one-liners for TN3270, FTP, RSH, USS.
3. CICS, IMS, DB2 attack surface quick reference.
4. JCL, REXX, HLASM injection patterns.
5. APF authorization and SSVT cheatsheet.
6. Operator console commands.
7. Top mainframe CVEs (2020-2026).
8. MITRE ATT&CK for Mainframe mapping.
9. Suspected-compromise response playbook (5 steps).

## RACF / ACF2 / Top Secret Command Matrix

The three security servers use different command vocabularies for the same conceptual operation. The matrix below maps the most-used operations across all three.

```text
Operation                  | RACF (TSO)               | ACF2                      | Top Secret
---------------------------|--------------------------|---------------------------|--------------------------
List a user                 | LISTUSER <uid>           | LIST <uid>                | LIS(DATA = <uid>)
List all users             | LISTUSER *               | LIST *                    | LIS(DATA = USER)
Add a user                 | ADDUSER <uid> ...        | INSERT <uid> ...          | ADDUSER <uid> ...
Alter a user               | ALTUSER <uid> ...        | CHANGE <uid> ...          | TSS PER(acid) ...
Delete a user              | DELUSER <uid>            | DELETE <uid>              | TSS REM(acid)
List a group               | LISTGRP <grp>            | LIST <grp>                | LIS(DATA = PROFILE)
List all groups            | LISTGRP *                | LIST *                    | LIS(DATA = PROFILE)
Add a group                | ADDGROUP <grp> ...       | INSERT <grp> ...          | ADDDEPT/<grp> ...
Connect user to group      | CONNECT <uid> GROUP(...) | ADD(LOGONID <uid>) GROUP  | TSS ADD(<uid>) DEPT(<grp>)
List dataset profile       | LISTDSD DATASET('<hlq>') ALL | LIST RESOURCE('<hlq>') | LIS(DATA = DATASET)
Add dataset profile        | ADDSD DATASET(...) ...   | INSERT RESOURCE(...) ...  | ADDSD
Alter dataset profile      | ALTDSD DATASET(...) ...  | CHANGE RESOURCE(...) ...  | TSS PER(...)
Delete dataset profile     | DELDSD DATASET(...)      | DELETE RESOURCE(...)      | TSS REM
Permit user to dataset     | PERMIT DATASET(...) ID(<uid>) ACCESS(READ) | SET RULES; $KEY(...) | TSS PERMIT(...)
List resource class        | SEARCH CLASS(<class>)    | LIST CLASS(<class>)       | LIS(DATA = RESOURCE)
Show special users         | LISTUSER * SPECIAL       | LIST * PRIV               | LIS(DATA = USER) ATTRIB(SPECIAL)
Show active options        | SETR LIST                | SHOW SAFSTAT              | TSS LIST(STC)
Audit on                    | SETROPTS AUDIT           | AUDIT ALL                 | TSS AUDIT
```

### RACF password rules

```ts
// Show current rules
SETR LIST

// Set password rotation interval
SETROPTS PASSWORD(INTERVAL(30))

// Require mixed alphanumeric
SETROPTS PASSWORD(RULES((ALPHANUM)))

// Remember last N passwords
SETROPTS PASSWORD(HISTORY(8))

// Require mixed case (where supported)
SETROPTS PASSWORD(MIXEDCASE)
```

### ACF2 password rules

```text
ACF
SET SYSIDS(PWD)
PSWD PSWD(VIO) MINLEN(8) MAXLEN(8) EXP(30) HIST(8)
```

### Top Secret password rules

```text
TSS MODI(PASSWORD) PWDMIN(8) PWDMAX(100) PWDEXP(30) PWDHIST(8)
```

## TN3270 / FTP / RSH / USS Recon One-Liners

### TN3270 recon

```bash
# Standard ports: 23 (plaintext), 992 (TLS), 2023 (alt plaintext), 2992 (alt TLS)
nmap -p 23,992,2023,2992 --script=tn3270-screen -sV $TARGET_SUBNET

# Banner grab via c3270 (one-shot, non-interactive)
echo "quit" | c3270 $TARGET_HOST:23 2>&1 | head -50

# Force TLS handshake to see cert
openssl s_client -connect $TARGET_HOST:992 -servername $TARGET_HOST -showcerts < /dev/null 2>&1 | head -40

# Capture the VTAM applid banner (helps identify the LPAR)
c3270 -t logon.txt $TARGET_HOST:23
# After connecting, look for "VTAM" or the APPLID in the banner panel.
```

### FTP recon (z/OS FTP server)

```bash
# Connect and enumerate HLQs via SITE commands
ftp $TARGET_HOST
> quote SITE LISTSYS
> quote SITE LISTCAT
> ls SYS1.*
> ls SYS1.PARMLIB
> quote SITE SBSENTRY
> quote SITE QUOTESOVERRIDE
> bye

# Scripted version for batch recon
cat > /tmp/mf-ftp-cmds.txt <<'EOF'
user IBMUSER SYS1
quote SITE LISTSYS
ls SYS1.PARMLIB
ls SYS1.LINKLIB
quote SITE SBSENTRY
bye
EOF
ncftpput -F -u IBMUSER -p SYS1 -f /tmp/mf-ftp-cmds.txt $TARGET_HOST /tmp /tmp/dummy-local 2>&1 | head -100
# (Adapt to the actual FTP client; pattern matters more than exact tool.)
```

### RSH and Rexec recon

```bash
# z/OS sometimes still exposes rsh / rexec for legacy batch submission
nmap -p 514,512,513 -sV $TARGET_SUBNET

# Attempt rexec with a list of common credentials
for u in IBMUSER SYSADM SYSOPER; do
  for p in SYS1 SYSADM SYSOPER PASS1; do
    echo "Trying $u:$p"
    rexec -u "$u" -p "$p" $TARGET_HOST 'LISTUSER *' 2>&1 | head -5
  done
done
# WARNING: only on engagements with explicit credential-bruteforce authorization.
```

### USS (Unix System Services) recon

```bash
# USS is reachable via SSH on most modern z/OS
ssh $TARGET_HOST -l IBMUSER 'id; uname -a; cat /etc/release'

# Inside USS, treat it like any Unix
# Enumerate users
ssh $TARGET_HOST 'getent passwd | head -50'

# Enumerate world-writable files in /etc
ssh $TARGET_HOST 'find /etc -perm -o+w -type f 2>/dev/null'

# Check for SUID binaries
ssh $TARGET_HOST 'find / -perm -u+s -type f 2>/dev/null | head -50'

# Check mVS attributes from USS
ssh $TARGET_HOST 'cat /etc/profile | grep -i "omvs\|mvs"'
```

## CICS / IMS / DB2 Attack Surface Cheatsheet

### CICS

```text
Surface                      | Where to look                                 | What to test
-----------------------------|-----------------------------------------------|-----------------------------------------
Transactions (TRANSID)       | CICS CSD or CSD-like repository              | Are protected transactions (CSGM, CSSF, CESN, CEOT, CEMT) restricted?
Transactions exposed         | RACF class CICSPCT (or XFACILIT on ACF2)     | LISTCAT for CICSPCT class; map to TRANSIDs
Resources (files, programs)  | CICS FCT, PCT, PPT                           | Can a user-submitted transaction READ a sensitive file? UPDATE?
START command (asynchronous) | EXEC CICS START                               | Can a transaction invoke another as a surrogate? (SURROGAT class)
Translator exits             | CICS SPA exit, mirror transactions           | Can user-supplied data trigger the translator with attacker-controlled values?
BMS maps                     | Mapset definitions                           | Are BMS maps honoring field length limits? (Buffer over-read territory)
CICS web services            | CICS TS Web Services / SOAP                  | WSDL discovery; XML parsing (XXE); WS-Security bypass
CICS transaction server jobs | Job log                                       | Are CICS region jobs surfacing sensitive data to OPERLOG?
EXCI / ECI interfaces        | Distributed program link                      | Are EXCI callers authenticated? Authorization?
```

### IMS

```text
Surface                      | Where to look                                 | What to test
-----------------------------|-----------------------------------------------|-----------------------------------------
Transactions (TPC)           | IMS TPC                                       | Are protected TPCs restricted in RACF?
Databases (DBD)              | IMS DBD                                       | What UACC do DBDs have? READ on financial DBD is high-risk.
PSB/PCB                      | IMS PSB/PCB                                   | What PCBs are exposed to which transactions?
ACB                          | IMS ACB (control block)                       | Are ACBs that permit UPDATE exposed?
DL/1 calls                   | DL/1 interface                                | Can a transaction issue DL/1 calls outside its declared PSB?
IMS Connect                  | TCP/IP listener (port 9999 typical)           | Is IMS Connect reachable from app-tier without auth?
OTMA                         | One-Transaction-Multiple-Address-Space        | Is OTMA bridging trusted regions without independent auth?
```

### DB2 for z/OS

```text
Surface                      | Where to look                                 | What to test
-----------------------------|-----------------------------------------------|-----------------------------------------
Auth IDs and privileges      | SYSIBM.SYSUSERAUTH, SYSUSER                   | Which auth IDs hold DBADM, SYSADM, BINDADD?
Grants on tables             | SYSIBM.SYSTABAUTH                             | Are there PUBLIC grants on sensitive tables?
Stored procedures            | SYSIBM.SYSROUTINES                            | Are external stored procedures registered? WLM-managed?
Stored procedure exits       | RACF class DSNR                               | Is class DSNR enabled? Who has EXECUTE on key SPs?
DB2 distributed data facility| DRDA listener (port 446 typical)             | Is DRDA reachable from app-tier? What auth?
DB2 REST service             | DB2 REST listener                             | Is REST enabled? Auth? SQL injection surface?
Plans and packages           | SYSIBM.SYSPLAN, SYSPACKAGE                    | Are plans/packages owned by low-priv IDs?
Buffer pool exhaustion       | Buffer pool config                            | Is there resource governing? ( runaway query DoS )
```

## JCL / REXX / HLASM Injection Patterns

### JCL injection

JCL injection happens when user-supplied input is concatenated into a JCL stream without escaping. The patterns below illustrate the bug and the fix.

```jcl
//BADJOB  JOB (ACCT),'USER',CLASS=A
//STEP1   EXEC PGM=IEBGENER
//SYSPRINT DD SYSOUT=*
//SYSIN    DD *
&PARM
//*
// VULNERABLE: If &PARM contains a line starting with //,
// it is treated as a new JCL statement.
```

Test payload (when authorized to demonstrate):

```text
&PARM=VALID VALUE
//BACKDOOR EXEC PGM=IEFBR14
//DD1    DD DSN=MYUSER.LINKLIB,DISP=SHR
```

The fix: validate that input does not contain `//` at column 1, and use symbolics with `&` only after sanitization. Use `SYSIN DD *` only for trusted input; otherwise use `SYSIN DD DSN(...)` with a pre-built dataset.

### REXX injection

REXX `INTERPRET` is the canonical injection sink.

```rexx
/* BAD */
PARSE ARG USER_INPUT
INTERPRET 'SAY ' USER_INPUT
/* VULNERABLE: USER_INPUT = 'dummy; EXIT' will execute the EXIT. */
```

Test payload (authorized):

```text
USER_INPUT = '"Hello"; "TSO SEND ''pwned''"';'
```

The fix: avoid `INTERPRET` with user-supplied data. If unavoidable, restrict the character set to `[A-Za-z0-9 _.-]` before `INTERPRET`.

### HLASM injection

HLASM injection is rarer but appears where mainframe assembler code accepts user input. The pattern is a buffer overflow or a control-capture via branch.

```asm
* BAD: accepting user input into a fixed-size buffer
USERIN   DS   CL8
         GET  MYIN,USERIN      * unbounded read
         MVC  TARGET,USERIN    * overflow if TARGET < 8
*
* TEST PAYLOAD (authorized):
*   Provide 16 bytes; the MVC overflows into adjacent storage.
*   If adjacent storage holds a return address, control-capture.
```

The fix: validate input length on the mainframe side using `TRT` or explicit length checks. Use `MVC` with explicit length operands that match the source buffer size.

## APF Authorization and SSVT Cheatsheet

### APF (Authorized Program Facility)

APF identifies libraries that are allowed to contain authorized programs. A program is authorized if it (a) comes from an APF library and (b) is link-edited with `AC(1)`.

```ts
// List APF libraries currently in effect
SETR LIST

// Static APF entries (from SYS1.PARMLIB(PROGxx))
// Look for: APF ADDSDSF(SMF1.SDSF.LOAD)
//    FORMAT(STATIC)
//    VOLUME(WRK001)

// Dynamic APF entries
// Look for: APF ADDSDSF(MYUSER.LINKLIB)
//    FORMAT(DYNAMIC)
//    VOLUME(WRK001)
```

Findings to flag on engagement:

```text
- APF library whose backing dataset has UACC > READ
- APF library whose backing dataset is on a user volume (not SYSRES)
- APF library that lives on a user-writable HLQ
- Dynamic APF entry for a dataset that does not exist on the volume
- APF library that contains user-contributed load modules (not from a vendor)
- SETR LIST output that disagrees with PROGxx (drift)
```

### SSVT (Subsystem Verification Test)

SSVT is IBM's tool for verifying APF library integrity. Run it periodically.

```ts
// Run SSVT via JCL
//SSVTRUN  JOB (ACCT),'SSVT',CLASS=A
//STEP1   EXEC PGM=ICHDS40,PARM='APF'
//SYSPRINT DD SYSOUT=*
//SYSUT1   DD DSN=SYS1.SSVT.CONTROL,DISP=SHR
//*
// SSVT produces a report of APF library integrity findings.
```

Interpret the report:

```text
LIBRARY NAME   VOLSER   STATUS
SYS1.LINKLIB   SYSRES   AUTHORIZED
SYS1.LPALIB    SYSRES   AUTHORIZED
MYUSER.LINKLIB WRK001   *** NOT AUTHORIZED ***   <-- finding
TEST.LINKLIB   WRK001   LIBRARY NOT FOUND         <-- finding (dangling APF entry)
```

## Operator Console Commands

The operator console is the high-ground of the LPAR. With OPERATOR attribute (or via SYSOPER in ACF2), an operator can issue commands that affect the whole LPAR.

```text
D A,L                  Display Active address spaces, List (every running region)
D ASM,L                Display Auxiliary Storage Manager, List (paging state)
D M=CPU                Display, MP CPU state
D PARMLIB              Display PARMLIB members in effect
D R,L                  Display Replies, List (outstanding WTORs)
D SMS,STORGRP          Display SMS storage group status
D XCF,SYSTEM           Display XCF systems coupled via CF
D TCP,NETSTAT          Display TCP/IP netstat summary
D U,VOL                Display Units, Volume status

Z EOD                  End of day: a major ops sequence
MODIFY jobname,COMMAND Send a modify command to a running job
START procname         Start a procedure (e.g., START CICSPROD)
STOP procname          Stop a procedure
CANCEL jobname         Cancel a running job (graceful)
FORCE jobname          Cancel a running job (immediate, less graceful)
VARY device,ONLINE     Vary a device online
VARY device,OFFLINE    Vary a device offline
DUMP COMM=reply        Take a dump of an address space
```

Security-relevant console actions:

```text
- STOP RACF would terminate the security server. Treat as P1 finding if reachable.
- MODIFY commands to JES2 can manipulate the spool. Treat as P1.
- VARY device,OFFLINE on a critical DASD can take down production. Treat as P1.
- DUMP on the RACF address space can produce a database snapshot.
```

## Top 10 Mainframe CVEs (2020-2026)

This is the short list of CVEs that engagement teams should have at the top of mind. CVSS and dates are from NVD at the time of writing; re-verify on NVD before relying on details.

```text
CVE-2022-22347 | IBM RACF undefined user session takeover                  | CVSS 8.1
              | A user could submit a job with USER=UNDEF and gain
              | execution under an undefined-user context.
              | Fix: apply IBM APAR and review IKJTSO AUTHUSER list.

CVE-2020-4689 | IBM z/OSMF Jazz for Service Management Server XSS         | CVSS 6.1
              | Reflected XSS in z/OSMF web UI.
              | Fix: apply z/OSMF cumulative PTF.

CVE-2021-29805| IBM abend recovery allows privilege escalation            | CVSS 7.8
              | Carefully crafted abend allows EOB escape.
              | Fix: apply z/OS HIPER PTF.

CVE-2020-4711 | IBM CICS TX standard vulnerable to SSRF                   | CVSS 7.5
              | SSRF in CICS TX web layer.
              | Fix: upgrade CICS TX to a fixed release.

CVE-2022-22363| IBM InfoSphere Information Server RCE                     | CVSS 9.1
              | Deserialization of untrusted data in Information Server.
              | Fix: apply fix pack; restrict network exposure.

CVE-2023-22464| IBM Aspera Faspex broken access control                   | CVSS 8.1
              | A low-priv user could escalate to admin.
              | Fix: upgrade Aspera Faspex.

CVE-2022-35785| IBM Data Risk Manager vulnerable to code execution        | CVSS 9.8
              | Multiple paths to RCE.
              | Fix: upgrade; restrict network exposure.

CVE-2020-4754 | IBM DB2 for z/OS denial of service                         | CVSS 7.5
              | Specific SQL pattern could exhaust agent pool.
              | Fix: apply DB2 PTF.

CVE-2021-29901| IBM Tivoli Netcool OMNIbus XSS                            | CVSS 6.1
              | Reflected XSS in OMNIbus web UI.
              | Fix: apply cumulative fix.

CVE-2024-1119 | IBM CICS TX unauthorized access (placeholder example)     | CVSS 7.5
              | (Verify the current CVE catalog before citing in a report.
              |  Placeholders are useful for cheatsheet layout; verify before
              |  relying on specifics.)
```

The catalog of mainframe-related CVEs is dynamic. Engagement teams should subscribe to the IBM Security Bulletins RSS feed and cross-reference with the CISA Known Exploited Vulnerabilities catalog before each engagement.

## MITRE ATT&CK for Mainframe Mapping

MITRE ATT&CK for Enterprise does not have a separate mainframe matrix, but most techniques translate. The mapping below pairs common mainframe adversary actions with their ATT&CK technique IDs.

```text
Tactic          | Technique ID | Technique Name          | Mainframe example
----------------|--------------|-------------------------|----------------------------------------
Initial Access  | T1078        | Valid Accounts          | Compromised TN3270 credentials
Initial Access  | T1190        | Exploit Public App      | z/OSMF web vulnerability
Initial Access  | T1195        | Supply Chain Compromise | Compromised vendor PTF (SolarWinds-style)
Persistence     | T1136        | Create Account          | ADDUSER creating a backdoor user
Persistence     | T1543        | Create/Modify Sys Proc  | Authorized program in APF library
Priv Esc        | T1078.004    | Cloud Accounts          | SPECIAL attribute abuse
Priv Esc        | T1068        | Setuid/Setgid           | APF-authorized program abuse
Defense Eva     | T1070        | Indicator Removal       | Suppressing SMF records
Defense Eva     | T1562        | Impair Defenses         | STOP RACF or MODIFY to disable logging
Credential Acc  | T1552        | Unsecured Credentials   | IRRDBU00 unload file with broad access
Discovery       | T1087        | Account Discovery       | LISTUSER * without authorization
Discovery       | T1046        | Network Service Scanning| z/OS port scan via USS
Lateral Mov     | T1021        | Remote Services         | TSO SEND, SURROGAT abuse
Collection      | T1005        | Data from Local System  | LISTDSD, dataset reads
Collection      | T1213        | Data from Info Repo     | SEAR API dataset enumeration
Exfil           | T1041        | Exfil Over C2 Channel   | TLS outbound from compromised web tier
Exfil           | T1567        | Exfil to Cloud Storage  | S3-bound extract (Capital One-style)
Impact          | T1485        | Data Destruction        | Wiper targeting mainframe (rare)
Impact          | T1490        | Inhibit System Recovery | STOP RACF, FORCE on critical address spaces
```

Use the mapping in two directions:

```text
1. From finding to technique: When documenting a finding, cite the ATT&CK ID
   so the client's SOC can map to their existing playbook.

2. From technique to hunt: When scoping a threat hunt, take a technique ID
   (e.g., T1136) and identify the mainframe-side signal (SMF 81 ADDUSER events).
```

## Response Playbook: Suspected Mainframe Compromise

When responding to a suspected compromise, follow the five steps below in order. Each step has a single owner and a defined exit criterion.

### Step 1: Contain (owner: IR lead; exit: spread halted)

```text
- Disable the suspected user IDs in RACF: ALTUSER <uid> NO NAME ...
  (or REVOKE <uid> if a simpler approach is desired first)
- Block the suspected source IP at the perimeter firewall and on the
  mainframe TN3270 listener.
- If the suspected persistence is via APF library: take the suspect library
  offline via dynamic APF removal (SETR NOPREFIX, then re-issue SETR LIST
  without the suspect entry).
- Do NOT delete evidence. Suspect user IDs should be REVOKEd, not DELUSERed.
- Document containment actions with timestamps.
```

### Step 2: Preserve (owner: forensics lead; exit: evidence captured)

```text
- Run IRRDBU00 to capture the RACF database as of containment time.
  (See payloads.md Section 14 for the JCL.)
- Capture SMF 30, 80, 81, 83, 14, 15, 110, 119 for the last 90 days.
- Capture the SYS1.BRODCAST dataset (connection history).
- Capture the operator log (OPERLOG) for the last 30 days.
- Take a flash copy of the suspect address spaces' DASD if feasible.
- Hash every captured artifact (SHA-256) and store the hashes separately.
```

### Step 3: Investigate (owner: IR lead; exit: root cause known)

```text
- Triage the SMF 80/81 events for the suspect user IDs.
- Trace the attack chain backward: where did the credentials come from?
- Triage the SMF 14/15 events for unexpected dataset reads.
- Triage the SMF 110 events for unexpected CICS transactions.
- Review ADDUSER/ALTUSER/PERMIT events outside change windows (SMF 81).
- Cross-correlate with the SIEM events on the distributed tier.
- Document the root cause with evidence pointers (SMF record IDs, timestamps).
```

### Step 4: Eradicate (owner: mainframe ops; exit: backdoor removed)

```text
- DELUSER every backdoor user created by the attacker.
- Remove every APF library the attacker added (SETR LIST audit).
- Reset credentials for every service account that the attacker might have touched.
  Reset to a fresh value via ALTUSER; do not reuse history.
- Re-issue the APF list from a known-good PROGxx.
- Re-IPL the LPAR from a known-good SYSRES if root-cause analysis indicates
  kernel-level compromise (rare but documented).
- Validate every PTF that should be applied is applied.
```

### Step 5: Recover and Learn (owner: IR lead + ops; exit: post-incident report)

```text
- Restore normal operations in phases; verify each phase before moving on.
- Run a full RACF audit (LISTUSER *, LISTGRP *, SETR LIST, LISTDSD on sensitive HLQs).
- Run SSVT to validate APF integrity.
- Convene a blameless post-incident review within 5 business days.
- Update the playbook with what was learned.
- File any regulatory notifications (PCI DSS, SOX, GDPR, etc.) within their windows.
- Schedule a follow-up assessment at 90 days to verify eradication.
```

## Closing Reference

This card is a companion to the longer `mainframe-security-playbook.md` (methodology) and to `payloads.md` (command reference). When a command here lacks context, the corresponding section in `payloads.md` or the playbook has the surrounding detail. The case-studies guide `real-world-incident-case-studies.md` provides the historical context for each pattern that this card summarizes.
