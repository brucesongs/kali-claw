---
name: privilege-escalation
description: "Privilege escalation is the process of elevating access from a low-privileged user context (standard user, service account, or limited shell) to root on Linux or SYSTEM/Administrator on Windows."
origin: openclaw
version: "0.1.18"
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
  domain: post-exploitation
  tool_count: 8
  guide_count: 3
  mitre: "TA0004-Privilege Escalation"
---




# Skill: Privilege Escalation

> **Supplementary Files**:
> - `payloads.md` — Complete command reference organized by escalation vector: automated enumeration, SUID/GTFOBins exploitation, sudo abuse, capabilities, kernel exploits, Windows token impersonation, service path hijacking, DLL hijacking, and UAC bypass
> - `test-cases.md` — Structured test case templates (TC-PE-001 to TC-PE-008) covering Linux and Windows privilege escalation scenarios with severity ratings and expected results

## Summary

Privilege Escalation skill domain covering post exploitation operations.

**Tools**: linpeas, winpeas, linux-exploit-suggester, pspy, GTFOBins, lolbas, sudo, capsh

**Domain**: post-exploitation

**MITRE ATT&CK**: TA0004-Privilege Escalation

## Description

Privilege escalation is the process of elevating access from a low-privileged user context (standard user, service account, or limited shell) to root on Linux or SYSTEM/Administrator on Windows. It is the critical bridge between initial foothold and full system control, determining the depth and impact of a penetration test or red team engagement.

This skill covers the complete escalation workflow: automated enumeration with linpeas/winpeas, manual verification of misconfigurations, exploitation of SUID binaries via GTFOBins, sudo rule abuse, Linux capabilities exploitation, cron job hijacking, kernel exploit identification and safe execution, and Windows-specific vectors including token impersonation, unquoted service paths, DLL hijacking, AlwaysInstallElevated, and UAC bypass techniques.

Core objective: systematically identify and exploit every viable escalation path from the current user context to the highest privilege level on the target system.

---

## Prerequisites

Before executing privilege escalation, ensure the following conditions are met:

1. **Established foothold** — A low-privilege shell or session on the target system (Linux or Windows)
2. **Authorization** — Written permission explicitly covering privilege escalation activities and credential harvesting
3. **Session stability** — A reliable connection (reverse shell, SSH session, or RDP) with reasonable persistence
4. **Tool transfer capability** — Ability to upload enumeration scripts and exploitation tools to the target
5. **Operational awareness** — Understanding of the target environment (production vs. test, criticality level, allowed impact)

---

## Use Cases

1. **Low-privilege shell on Linux** — Escalate from a www-data or standard user shell to root via SUID binaries, sudo misconfigurations, cron abuse, or kernel exploits
2. **Low-privilege shell on Windows** — Escalate from a standard user to SYSTEM or Administrator via token impersonation, service misconfigurations, or UAC bypass
3. **Container escape context** — Identify capabilities, SUID binaries, or host-mounted filesystems that enable breakout from a container to the host
4. **Domain environment escalation** — Leverage local privilege escalation as a stepping stone to domain-level compromise through credential harvesting and lateral movement
5. **Red team assessment depth** — Demonstrate the full impact of an initial compromise by reaching the highest privilege level, proving that the foothold leads to complete system control

---

## Variants

| Escalation Type | Platform | Risk Level | Typical Vector |
|-----------------|----------|------------|----------------|
| SUID Binary Exploitation | Linux | Medium | Non-standard SUID binary with GTFOBins entry |
| sudo Misconfiguration | Linux | Medium | NOPASSWD, wildcard, LD_PRELOAD rules |
| Capabilities Abuse | Linux | Medium | cap_setuid, cap_dac_read_search on exploitable binary |
| Cron Job Hijacking | Linux | Medium | Writable cron script or PATH hijack |
| Kernel Exploit | Linux | High | Known CVE matching running kernel version |
| NFS no_root_squash | Linux | Medium | Exported filesystem with root_squash disabled |
| Docker/LXC Group | Linux | Medium | User in docker group can escape to host root |
| Token Impersonation | Windows | Medium | SeImpersonatePrivilege / Potato attacks |
| Service Path Hijack | Windows | Medium | Unquoted service path with writable directory |
| DLL Hijacking | Windows | Medium | Writable directory in DLL search order |
| AlwaysInstallElevated | Windows | Medium | MSI packages install as SYSTEM |
| UAC Bypass | Windows | Low | Auto-elevation of built-in Windows binaries |
| Stored Credentials | Windows | Low | Credentials in registry, files, or vault |

---

## Core Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **linpeas** | Automated Linux privilege escalation enumeration; checks SUID, sudo, capabilities, cron, NFS, kernel, and hundreds of misconfiguration vectors | `./linpeas.sh -a 2>/dev/null \| tee linpeas.out` |
| **winpeas** | Automated Windows privilege escalation enumeration; checks services, tokens, registry, UAC, stored credentials, and DLL hijacking paths | `.\winPEAS.exe quiet cmd fast` |
| **linux-exploit-suggester** | Kernel version-based exploit recommendation; maps running kernel to known CVEs with reliability ratings | `./linux-exploit-suggester.sh --uname "5.4.0"` |
| **pspy** | Monitor running processes without root; discover cron jobs, scheduled tasks, and hidden root processes in real time | `./pspy64 -pf -i 1000` |
| **GTFOBins** | Reference database of Unix binaries exploitable for privilege escalation through SUID, sudo, or capabilities | Reference: https://gtfobins.github.io |
| **lolbas** | Reference database of Windows living-off-the-land binaries usable for escalation, execution, or credential access | Reference: https://lolbas-project.github.io |
| **sudo** | Exploit sudo misconfigurations: NOPASSWD entries, wildcard injection, env_keep, and rule-based bypasses | `sudo -l; sudo /usr/bin/vim -c ':!/bin/bash'` |
| **capsh** | Enumerate and decode Linux capabilities on binaries; identify exploitable capability assignments | `capsh --print; getcap -r / 2>/dev/null` |

---

## Methodology

### Attack Chain

```
Enumeration                    Identification                 Exploitation
(linpeas, winpeas,           (sudo -l, SUID find,           (GTFOBins, kernel exploit,
 manual checks)               getcap, pspy)                  token impersonation)
      |                              |                              |
      v                              v                              v
                           Escalation                    Persistence & Documentation
                           (root/SYSTEM shell)           (document path, clean artifacts)
```

**Phase details**:

1. **Enumerate** — Run linpeas (Linux) or winpeas (Windows) for automated enumeration. Collect system information: kernel version, OS release, running processes, installed packages, network configuration, and user context. This phase casts the widest possible net to identify all potential escalation vectors.

2. **Identify** — Manually verify and prioritize the enumeration findings. Check sudo permissions (`sudo -l`), locate SUID binaries (`find / -perm -4000`), enumerate capabilities (`getcap -r /`), inspect cron jobs (`/etc/crontab`, `crontab -l`), and review running services. On Windows, examine token privileges (`whoami /priv`), service configurations, registry keys, and UAC settings. Prioritize vectors by reliability and impact.

3. **Exploit** — Apply the appropriate exploitation technique for the identified vector. Use GTFOBins for SUID/sudo binary exploitation, linux-exploit-suggester output for kernel-level attacks, token impersonation for Windows privilege abuse, or lolbas techniques for living-off-the-land escalation. Execute with caution, especially for kernel exploits which can destabilize the target.

4. **Escalate** — Achieve root (Linux) or SYSTEM/Administrator (Windows) access through the exploited vector. Verify the escalation with `id` or `whoami` commands. Harvest credentials from the elevated context for further lateral movement if within scope.

5. **Persist** — Document the complete escalation path including every command executed, every file modified, and every vulnerability exploited. Record the before/after privilege context. Clean up any artifacts (uploaded tools, temporary files) unless persistence testing is explicitly authorized.

### Defense Perspective

| Defense Measure | Escalation Vector Mitigated | Description |
|-----------------|---------------------------|-------------|
| Principle of Least Privilege | SUID, sudo, capabilities | Remove unnecessary SUID bits, restrict sudo rules, drop unused capabilities |
| Kernel Patching | Kernel exploits | Maintain current kernel versions; apply security patches promptly |
| Credential Guard / LSA Protection | Token impersonation | Protect LSASS memory; prevent SeDebugPrivilege abuse |
| UAC Configuration | UAC bypass | Set UAC to "Always Notify"; restrict auto-elevation for built-in accounts |
| Service Hardening | Service path, DLL hijacking | Quote all service paths; use explicit paths; implement DLL search order |
| File Integrity Monitoring | SUID/cron modification | Alert on changes to SUID bits, cron files, and system binaries |
| Application Whitelisting | lolbas/GTFOBins abuse | Restrict executable locations; block unapproved binaries |

---

## Practical Steps

### Linux Escalation Workflow

1. Run `linpeas.sh -a` for automated enumeration
2. Check `sudo -l` for misconfigured rules
3. Run `find / -perm -4000 -type f 2>/dev/null` for SUID binaries
4. Run `getcap -r / 2>/dev/null` for capabilities
5. Inspect `/etc/crontab` and `crontab -l` for cron abuse
6. Check `cat /proc/version; uname -r` for kernel exploits
7. Run `linux-exploit-suggester.sh` to map kernel CVEs
8. Verify with `pspy64` for hidden scheduled processes
9. Exploit highest-reliability vector first
10. Confirm with `id` showing uid=0(root)

### Windows Escalation Workflow

1. Run `winPEAS.exe quiet cmd fast` for automated enumeration
2. Check `whoami /priv` for exploitable token privileges
3. Run `systeminfo` for OS version and patch level
4. Check `net user; net localgroup administrators` for user context
5. Inspect `sc qc <service>` for unquoted service paths
6. Check registry for AlwaysInstallElevated and stored credentials
7. Run `accesschk.exe` for writable service directories
8. Exploit token impersonation if SeImpersonatePrivilege present
9. Attempt UAC bypass if standard user can auto-elevate
10. Confirm with `whoami` showing SYSTEM or Administrator

---

## Key Decisions

- **Kernel exploit as last resort**: Kernel exploits carry the highest risk of system instability or crash. Always attempt misconfiguration-based escalation (SUID, sudo, cron, services) before kernel exploits. If a kernel exploit is necessary, verify the target kernel version precisely and test in an identical environment first when possible.
- **Enumeration depth vs. stealth**: Automated tools like linpeas and winpeas are thorough but noisy. In stealth-sensitive engagements, use manual enumeration commands selectively. In standard penetration tests, run automated tools for comprehensive coverage and document all findings.
- **Living-off-the-land vs. uploaded tools**: Prefer GTFOBins/lolbas techniques using existing system binaries over uploading custom exploits. System binaries are less likely to trigger antivirus or EDR alerts, and they leave fewer artifacts on disk.

---

## Quality Criteria

- Every escalation path must be documented with step-by-step reproduction instructions
- Before and after privilege levels must be captured (screenshots of `id` / `whoami` output)
- All attempted vectors must be reported, including failed attempts — they reveal defense effectiveness
- Kernel exploit usage must include justification for why safer alternatives were insufficient
- Cleanup of all uploaded tools and temporary modifications must be verified before disconnection
- All findings must be mapped to MITRE ATT&CK technique IDs for standardized reporting

---

## Escalation Priority Matrix

| Priority | Vector | Why |
|----------|--------|-----|
| 1 (Try first) | SUID/GTFOBins, sudo misconfig | Reliable, no system risk, fast |
| 2 | Capabilities, cron abuse | Reliable, requires specific conditions |
| 3 | Service misconfigurations (Windows) | Moderate reliability, environment-dependent |
| 4 | Token impersonation (Windows) | Highly reliable when SeImpersonate present |
| 5 (Last resort) | Kernel exploits | High crash risk, version-specific |

**Rule**: Never attempt a kernel exploit until all misconfiguration vectors have been exhausted and documented.

---

## Common Pitfalls

- **Running linpeas/winpeas without reviewing output context**: These tools produce hundreds of lines of output flagged with color codes. Blindly following the first highlighted finding without understanding the system context can waste time on false positives. Cross-reference tool findings with manual verification before attempting exploitation.
- **Attempting kernel exploits without version verification**: A single kernel version digit difference can mean the exploit will crash the target instead of elevating privileges. Always verify the exact kernel version with `uname -r` and cross-reference with the exploit's supported range.
- **Ignoring operational security during escalation**: Running privilege escalation tools modifies filesystem timestamps, creates log entries, and may trigger EDR alerts. Maintain a modification log and plan cleanup before executing escalation commands.

---

## Anti-Patterns

- **Skipping enumeration**: Jumping straight to exploitation without thorough enumeration leads to missed vectors and wasted time. Always complete the full enumeration phase before attempting any exploit.
- **Running linpeas as root**: Running automated enumeration tools with elevated privileges defeats the purpose of identifying escalation vectors from the current user context.
- **Ignoring failed exploits**: Failed exploitation attempts provide valuable intelligence about defensive controls. Document every attempt with the exact error or behavior observed.
- **Kernel exploit on production**: Kernel exploits can cause system panics and reboots. Obtain explicit written authorization and schedule during maintenance windows for production targets.
- **Neglecting cleanup**: Leaving enumeration scripts, modified SUID binaries, or temporary cron entries on the target creates evidence and potential instability.

---

## Reporting and Documentation

Privilege escalation reports must include: the initial user context and privilege level, the enumeration methodology (automated + manual), every escalation vector identified, the vector successfully exploited, step-by-step reproduction commands, proof of escalation (screenshots), and recommended remediation for each identified vector. Map all techniques to MITRE ATT&CK technique IDs (e.g., T1548.001 — Abuse Elevation Control Mechanism: Setuid and Setgid). Document the risk rating for each finding based on exploitability and impact.

---

## Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| linpeas output is overwhelming | Too many findings to parse | Use `grep` filters: `linpeas.out \| grep -i "peass\|suid\|sudo"` |
| SUID binary not in GTFOBins | Custom or uncommon binary | Check binary with `strings`, `ltrace`, `strace` for exploitable behavior |
| sudo exploit fails after `sudo -l` shows vulnerability | Environment variables or PATH issues | Use `sudo -V` to check version; try absolute paths |
| Kernel exploit compilation fails | Missing gcc or headers | Cross-compile on attacker machine; use static binary |
| Token impersonation returns access denied | Patched OS or EDR blocking | Check Windows build; try alternative Potato variant; check EDR logs |
| Cron payload not executing | Wrong schedule or permission | Verify with `pspy`; check cron log: `grep CRON /var/log/syslog` |
| getcap returns empty | No capabilities set or filesystem mounted nosuid | Fall back to SUID/sudo vectors; check mount options with `mount \| grep nosuid` |

---

## Legal and Ethical Considerations

Privilege escalation explicitly accesses resources and data beyond the initial compromise scope. The engagement letter must specifically authorize privilege escalation activities. Kernel exploits carry denial-of-service risk; obtain explicit approval before attempting kernel-level attacks on production systems. Credential harvesting during escalation (e.g., `/etc/shadow`, SAM database) must be reported and handled according to the engagement's data handling requirements.

---

## Integration with Other Skills

Privilege escalation receives initial access from `skills/network-pentest/`, `skills/web-xss/`, `skills/web-sqli/`, and `skills/web-auth-bypass/`. Successful escalation feeds into `skills/post-exploitation/` for persistence and lateral movement. Credential material harvested during escalation (hashes, SSH keys, tokens) feeds into `skills/password-attack/` for cracking. Container escape findings relate to `skills/container-security/`. Active Directory escalation connects to `skills/api-security/` for domain-level attack paths.

---

## Learning Resources

- **Skill supplementary files**: `payloads.md`, `test-cases.md`
- **Skill guides**: `guides/linux-privilege-escalation-enumeration-guide.md`, `guides/windows-privilege-escalation-attack-guide.md`, `guides/kernel-exploit-safety-guide.md`
- **Related Skills**: `skills/post-exploitation/SKILL.md`, `skills/container-security/SKILL.md`, `skills/password-attack/SKILL.md`
- **External Resources**:
  - GTFOBins — https://gtfobins.github.io (Unix binary exploitation reference)
  - LOLBAS — https://lolbas-project.github.io (Windows living-off-the-land reference)
  - HackTricks Privilege Escalation — https://book.hacktricks.wiki (comprehensive privesc techniques)
  - PayloadsAllTheThings — https://github.com/swisskyrepo/PayloadsAllTheThings (escalation payload collection)
  - MITRE ATT&CK Privilege Escalation — https://attack.mitre.org/tactics/TA0004/ (technique taxonomy)

---

_All privilege escalation techniques must be executed only within written authorization scope. Unauthorized system access is illegal._

_Last updated: 2026-06-04_
