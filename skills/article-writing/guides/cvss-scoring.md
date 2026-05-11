# CVSS Scoring Guide for Pentest Reports

Quick reference for calculating and justifying CVSS 3.1 scores in penetration test reports.

## CVSS 3.1 Vector Breakdown

### Attack Vector (AV)

- **Network (N)**: Remotely exploitable (most vulnerabilities)
- **Adjacent (A)**: Requires local network access (ARP spoofing, local MitM)
- **Local (L)**: Requires local access (privilege escalation)
- **Physical (P)**: Requires physical access (USB attacks, console access)

### Attack Complexity (AC)

- **Low (L)**: No special conditions required
- **High (H)**: Requires specific conditions (timing, race condition, advanced technique)

### Privileges Required (PR)

- **None (N)**: Unauthenticated attack
- **Low (L)**: Requires regular user account
- **High (H)**: Requires administrator/privileged account

### User Interaction (UI)

- **None (N)**: No user action required
- **Required (R)**: Requires victim action (click link, open file)

### Scope (S)

- **Unchanged (U)**: Vulnerability affects only the vulnerable component
- **Changed (C)**: Vulnerability affects resources beyond its security scope (e.g., container escape, SSRF to internal network)

### Impact (C/I/A)

- **High (H)**: Total compromise of confidentiality/integrity/availability
- **Low (L)**: Some information disclosed/modified, limited impact
- **None (N)**: No impact on this dimension

---

## Common Vulnerability CVSS Scores

| Vulnerability | Vector | Score | Severity |
|--------------|--------|-------|----------|
| Unauthenticated RCE | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 | Critical |
| SQL Injection (unauth) | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 | Critical |
| Authenticated RCE | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 8.8 | High |
| SQL Injection (auth) | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 8.8 | High |
| SSRF to internal network | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N | 7.7 | High |
| Stored XSS | AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N | 5.4 | Medium |
| Reflected XSS | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | 6.1 | Medium |
| IDOR | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5 | Medium |
| Info Disclosure (versions) | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 5.3 | Medium |
| Local Privilege Escalation | AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 7.8 | High |

---

## Scoring Decision Trees

### Is it Critical (9.0-10.0)?

- Unauthenticated remote code execution? → YES
- Unauthenticated data breach (all records)? → YES
- Complete system compromise without auth? → YES
- Otherwise → NO, evaluate for High

### Is it High (7.0-8.9)?

- Authenticated RCE? → YES
- Privilege escalation? → YES
- SQL injection with data access? → YES
- SSRF to internal network? → YES
- Otherwise → NO, evaluate for Medium

### Is it Medium (4.0-6.9)?

- XSS? → YES (usually)
- IDOR? → YES
- CSRF? → YES
- Auth bypass (limited scope)? → YES
- Info disclosure (non-trivial)? → YES
- Otherwise → NO, evaluate for Low

---

## Justification Templates

### Critical (9.0-10.0)

```
CVSS: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

This vulnerability is rated Critical due to:
- Unauthenticated remote exploitation (AV:N, PR:N)
- No special conditions required (AC:L, UI:N)
- Complete impact on confidentiality, integrity, and availability (C:H/I:H/A:H)

An attacker can fully compromise the system without credentials, leading to data breach, service disruption, and lateral movement potential.
```

### High (7.0-8.9)

```
CVSS: 8.8 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)

This vulnerability is rated High due to:
- Remote exploitation with low-privilege authentication (AV:N, PR:L)
- Complete impact on all CIA triad dimensions (C:H/I:H/A:H)

While authentication is required, standard user accounts are sufficient for exploitation, significantly expanding the attack surface.
```

### Medium (4.0-6.9)

```
CVSS: 5.4 (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N)

This vulnerability is rated Medium due to:
- Requires user interaction (UI:R) — victim must click malicious link
- Limited impact (C:L/I:L) — affects individual users, not system-wide
- Scope change (S:C) — XSS executes in victim's browser context

While exploitable, the attack requires social engineering and affects individual users rather than the entire system.
```

---

## Common Mistakes

### Mistake 1: Overrating Info Disclosure

**Wrong**: Info disclosure of server version → Critical
**Right**: Info disclosure of server version → Medium (CVSS 5.3)

Justification: While info disclosure aids reconnaissance, it does not directly compromise data.

### Mistake 2: Underrating Authenticated Vulns

**Wrong**: Authenticated SQL injection → Medium
**Right**: Authenticated SQL injection → High (CVSS 8.8)

Justification: Authentication requirement lowers score slightly, but full database access warrants High severity.

### Mistake 3: Ignoring Scope Change

**Wrong**: SSRF to internal network → S:U
**Right**: SSRF to internal network → S:C

Justification: SSRF affects resources beyond the vulnerable application (internal services), so scope is Changed.

---

## Calculator Links

- **CVSS 3.1 Calculator**: https://www.first.org/cvss/calculator/3.1
- **NVD Calculator**: https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator

---

## Quick Reference Card

```
+--------+--------+--------+--------+--------+--------+--------+--------+
|   AV   |   AC   |   PR   |   UI   |   S    |   C    |   I    |   A    |
+--------+--------+--------+--------+--------+--------+--------+--------+
| N A L P| L  H   | N L H  | N  R   | U  C   | N L H  | N L H  | N L H  |
+--------+--------+--------+--------+--------+--------+--------+--------+

Critical: 9.0-10.0
High: 7.0-8.9
Medium: 4.0-6.9
Low: 0.1-3.9
```
