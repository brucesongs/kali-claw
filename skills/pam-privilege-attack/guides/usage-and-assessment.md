# pam-privilege-attack — Usage Instructions & Capability Assessment

> **Assessment Date**: 2026-08-09 | **Reviewer**: Claude (automated + human review) | **Version**: v0.2.0.2
> **Overall Score**: **81/100 (Excellent)** | **Findings**: P0:0 P1:0 P2:1 P3:2
> **Wave 1 Batch 1** (7th SKILL assessed)

## Quick Assessment Dashboard

| Dimension | Score (1-5) | Rationale |
|-----------|-------------|-----------|
| 1. Compliance | **5** | 0/0/0 |
| 2. Content Completeness | **5** | payloads 2463 + test-cases **445** (best ratio in batch, 18%) + 1 guide; 14 H2 + 24 H3 |
| 3. Command Syntax | **4** | Linux PAM tools available (pam_*.so all present); pamtester / unix_chkpwd missing; commercial PAM (CyberArk/BeyondTrust) is theory-only |
| 4. References | **5** | **24 URLs + 3 CVEs** — best URL density in batch |
| 5. MITRE/OWASP Alignment | **4** | 7 ATT&CK T-codes (T1098/T1550.x/T1552.x); frontmatter only T1552 (1 of 7) |
| 6. Usability | **4** | Clear commercial PAM coverage (CyberArk/BeyondTrust/Delinea/ManageEngine); thin on free PAM alternatives |
| **Weighted Total** | **81/100** | **Excellent** — top-tier SKILL |

## Usage Instructions

### What this SKILL does
Privileged Access Management (PAM) attack surface: CyberArk, BeyondTrust, Delinea (formerly Thycotic), ManageEngine PAM360. Covers: vault credential extraction, session hijacking, EPM (Endpoint Privilege Management) bypass, SSH key theft, just-in-time (JIT) elevation abuse.

### When to use it
1. Enterprise pentest where target uses CyberArk/BeyondTrust/Delinea for credential vaulting
2. Red team assessment of just-in-time privilege elevation
3. Insider threat assessment (vault admin abuse)
4. PAM deployment audit (implementation review)
5. Incident response involving suspected vault compromise

### How to start
1. **Identify PAM vendor**: from recon (CyberArk Password Vault web on 443/Apache; BeyondTrust on 443/IIS; Delinea Secret Server on 443/IIS)
2. **Assess vault metadata**: PSMP (Privileged Session Manager SSH) on 22/SSH for CyberArk; check `psmapp.appid` cookie
3. **Check default accounts**: CyberArk Administrator / Auditor / PasswordManager (well-known defaults in older versions)
4. **Look for EPM agent**: BeyondTrust EPM, CyberArk EPM, Delinea Endpoint Privilege Manager — local privilege escalation vector if present
5. **SSH key recovery**: if CyberArk PSMP in use, all admin SSH flows through it; compromise PSMP = compromise all targets

### Common pitfalls
- **Vault admin = domain admin equivalent**: vault contains all privileged credentials; treat vault admin with highest caution
- **PSM recording gaps**: some protocols (RDP file transfer, clipboard) may not be recorded in older PAM versions
- **EPM bypass**: native Windows token manipulation (`NtSetInformationToken`) often bypasses userland EPM
- **API token leakage**: CyberArk REST API tokens often leak in custom automation scripts
- **Emergency access accounts**: CyberArk Break Glass / BeyondTrust Recovery Console are often shared secrets — high-value target

### Cross-references
- `secret-management-attack` (broader secret infra: HashiCorp Vault, AWS Secrets Manager) — switch for non-PAM secret stores
- `privilege-escalation` (OS-level PE) — switch when already on host and seeking higher privileges
- `post-exploitation` (general post-exploit) — switch for breadth after initial foothold
- `ad-cs-abuse` — switch for Active Directory Certificate Services attacks
- `cloud-identity-attack` — switch for cloud IAM (Entra ID / Okta)

## Capability Assessment Detail

### D1: 5/5 | D2: 5/5 (445 test-case lines is excellent ratio)

### D3: 4/5
- **Tool availability on VM**:
  - ✓ Linux PAM modules (`/usr/lib/aarch64-linux-gnu/security/pam_*.so`: pam_access, pam_canonicalize_user, pam_debug, pam_deny, etc.)
  - ✓ `/etc/pam.d/` configuration structure present
  - ✓ `/etc/ssh/sshd_config` (sshd present)
  - ✗ `pamtester` (testing tool — `apt install pamtester`)
  - ✗ `unix_chkpwd` (helper; usually in libpam-runtime but missing here)
  - ✗ Commercial PAM tools (CyberArk/BeyondTrust/Delinea) — theory-only by nature
- **Static review**: payloads reference real CyberArk CLIs (PACLI, cpass, PSMP), BeyondTrust API, Delinea Secret Server API — all valid
- **Evidence**: [evidence/2026-08-09/summary.md](../evidence/2026-08-09/summary.md)

### D4: 5/5
- 24 URLs (CyberArk docs, BeyondTrust docs, vendor security advisories, etc.) — best URL density in Wave 1 Batch 1
- 3 CVEs (need more — CyberArk CVE-2025-26652, BeyondTrust RSA exploitation 2024)

### D5: 4/5
- 7 ATT&CK T-codes (T1098 Account Manipulation, T1550 Use Alternate Auth Material, T1550.002 Pass the Hash, T1550.004 Web Session Cookie, T1552 Unsecured Credentials, T1552.001 Credentials In Files, T1552.004 Private Keys) — strong
- Frontmatter only `T1552-Unsecured Credentials` (1 of 7) — under-represents

### D6: 4/5
- Strengths: clear per-vendor sections (CyberArk / BeyondTrust / Delinea / ManageEngine) with specific commands and APIs
- Weaknesses: thin coverage of open-source PAM alternatives (Wallix, Xton, Devolutions); 1 guide only

## Findings & Priorities

| ID | Priority | Description | Recommended Fix |
|----|----------|-------------|-----------------|
| F-001 | P2 | `pamtester` / `unix_chkpwd` missing in Kali 2026.1 default | Add `apt install pamtester libpam-runtime` to payloads |
| F-002 | P3 | Only 3 CVE references despite active vendor CVE history | Add: CyberArk CVE-2025-26652 (PSM), BeyondTrust breach (2024-12), Delinea advisories |
| F-003 | P3 | Frontmatter mitre field narrow (1 of 7 T-codes) | Expand to `"T1098-Account Manipulation, T1550-Use Alternate Authentication Material, T1550.002-Pass the Hash, T1550.004-Web Session Cookie, T1552-Unsecured Credentials, T1552.001-Credentials In Files, T1552.004-Private Keys"` |
| F-004 | P3 | Only 1 guide; needs at least playbook | Add `guides/pam-privilege-attack-playbook.md` (vendor-by-vendor workflow) |

## Validation Evidence

- [evidence/2026-08-09/summary.md](../evidence/2026-08-09/summary.md)
- [evidence/2026-08-09/lint.json](../evidence/2026-08-09/lint.json)
- Kali VM: parallels@10.211.55.5 (Kali 2026.1, aarch64)

## Reviewer Sign-off
- Reviewer: Claude (Wave 1 Batch 1, SKILL 5/5 — batch complete)
- Approved by: _______________ Date: _______
