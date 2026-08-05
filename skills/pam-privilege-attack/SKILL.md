---
name: pam-privilege-attack
description: "Privileged Access Management (PAM) vendor abuse — CyberArk PVWA/PSM/EPV/AIM/CFE, BeyondTrust PRA/Password Safe/Identity Security Insights, Delinea Secret Server/Privilege Manager, One Identity Safeguard, ManageEngine Password Manager Pro, WALLIX Bastion, Devolutions Server, Xton Core. Covers PVWA auth bypass (CVE-2025-32564 area), CyberArk safe enumeration via WebSocket, credential file (.cue) theft and decryption, PSM session hijacking, AIM/CCP provider abuse, master key escrow analysis, BeyondTrust SAML account injection (CVE-2022-2451), Password Safe API abuse, session recording tampering, Delinea OAuth token theft, DPAPI-protected agent config extraction, distributed engine lateral movement, One Identity Safeguard SSL pinning bypass, ManageEngine PMP API key enumeration, PostgreSQL backend extraction (CVE-2022-28226 area), pass-the-hash in PAM contexts, golden ticket interaction with PAM credential rotation, and modern ransomware operator TTPs targeting PAM (BlackCat/ALPHV, LockBit, Royal/BlackSuit)."
origin: kali-claw
version: "0.2.0.2"
compatibility:
  - claude-code
  - claude-sonnet-4.5
  - cursor
  - windsurf
  - openclaw
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
metadata:
  domain: pam-privilege-attack
  category: privileged-access-management
  tool_count: 18
  guide_count: 1
  mitre: "T1552-Unsecured Credentials"
  keywords:
    - PAM
    - privileged access management
    - CyberArk
    - PVWA
    - PSM
    - EPV
    - AIM
    - CFE
    - BeyondTrust
    - PRA
    - Password Safe
    - Delinea
    - Thycotic
    - Secret Server
    - One Identity
    - Safeguard
    - ManageEngine
    - Password Manager Pro
    - PMP
    - WALLIX
    - Bastion
    - Devolutions
    - Xton
    - credential file
    - .cue file
    - DPAPI
    - SAML injection
    - CVE-2025-32564
    - CVE-2022-2451
    - CVE-2022-28226
    - session hijacking
    - just-in-time
    - JIT access
    - BlackCat
    - ALPHV
    - LockBit
  last_reviewed: "2026-07-26"
---

# Skill: Privileged Access Management (PAM) Privilege Attack

> **Supplementary Files**:
> - `payloads.md` -- Per-vendor payload catalogs for CyberArk, BeyondTrust, Delinea, One Identity, ManageEngine PMP, WALLIX, Devolutions, Xton Core; plus cross-cutting patterns (cred file theft, session hijack, API key abuse, JIT workflow bypass, PAM-aware pass-the-hash) (70+ code blocks, 2,200+ lines)
> - `test-cases.md` -- Structured test case templates (15 cases TC-PM-001 through TC-PM-015 covering presence recon, vendor-specific abuse, and cross-cutting patterns)
> - `guides/pam-privilege-attack-playbook.md` -- End-to-end playbook: PAM recon, vendor identification, exploitation, credential extraction, lateral movement to actual privileged targets, JIT persistence, lab setup, and detection guidance

## Summary

PAM Privilege Attack skill domain covering vendor-specific compromise of Privileged Access Management platforms. PAM systems (CyberArk, BeyondTrust, Delinea, One Identity, ManageEngine, WALLIX, Devolutions, Xton) sit at the very top of the enterprise trust stack — they hold the credentials for root, Domain Admin, cloud root, database SA, and network device enable accounts. Compromising the PAM is equivalent to compromising every privileged asset the PAM manages. Recent ransomware operators (BlackCat/ALPHV, LockBit, Royal/BlackSuit) explicitly target PAM infrastructure as the first step in their affiliate playbooks because once the PAM falls, downstream extortion leverage is total.

**Domain**: privileged-access-management

**MITRE ATT&CK**: T1552-Unsecured Credentials, T1552.001-Credentials In Files, T1552.004-Private Keys, T1550-Use Alternate Authentication Material, T1550.002-Pass the Hash, T1550.004-Web Session Cookie, T1098-Account Manipulation

## Differentiation from Adjacent Skills

This skill is **deliberately scoped** to vendor-specific PAM platforms. It does not duplicate general secret-management coverage.

| Topic | `secret-management-attack` | `ad-ldap-attack` / `ad-cs-abuse` | `pam-privilege-attack` (this skill) |
|-------|----------------------------|-----------------------------------|-------------------------------------|
| Scope | HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, CI/CD pipeline secrets, source-code secrets | Active Directory, AD CS PKI | CyberArk, BeyondTrust, Delinea, One Identity, ManageEngine PMP, WALLIX, Devolutions, Xton |
| Credential type | Cloud API keys, tokens, CI variables, source-code secrets | NTLM hashes, Kerberos tickets, X.509 certs | Vaulted privileged credentials, PSM session tokens, PAM API keys, JIT access workflows |
| Attack surface | Cloud provider APIs, Vault HTTP API, git history, image layers | LDAP, Kerberos, AD CS RPC/HTTP | Vendor-specific HTTP/WS/RPC APIs, credential file formats (`.cue`, DPAPI blobs), session brokers |
| Primary attacker | Cloud-aware red team, secret sprawl auditor | Internal AD red teamer | Ransomware operator, insider threat, third-party access abuser |
| Real-world anchor | Codecov, CircleCI, LastPass, Toyota | PetitPotam, Certifried, NotPetYa | BlackCat PAM targeting (Mandiant 2023), LockBit CyberArk playbook (CrowdStrike 2023), Royal/BlackSuit BeyondTrust abuse |

When the engagement involves the strings `CyberArk`, `PVWA`, `PSM`, `EPV`, `Password Vault`, `BeyondTrust`, `Password Safe`, `Privileged Remote Access`, `Secret Server`, `Thycotic`, `Delinea`, `One Identity`, `Safeguard`, `Password Manager Pro`, `PMP`, `WALLIX Access Manager`, `Bastion`, `Devolutions Server`, `Xton Core`, or specific artifacts like `.cue` files, `Vault.ini`, `btl\` (BeyondTrust session ID prefixes), route through this skill. If both PAM and AD are in scope, chain: PAM compromise → credential extraction → use the harvested privileged account with `ad-ldap-attack` or `cloud-security` techniques for downstream dominance.

## Description

A PAM platform is fundamentally a credential broker: it accepts a request from an authenticated user ("I need to SSH to `prod-db-01` as `root`"), authenticates and authorises the request against policy, retrieves the privileged credential from an encrypted vault, brokers the connection (often via a jump host / session manager), records the session, and rotates the credential on completion. Every step in this flow is an attack surface — the authentication layer (PVWA logon, PRA SAML, PMP API key), the authorization layer (safe ACLs, JIT workflow bypass), the retrieval layer (credential file decryption, AIM provider abuse), the brokering layer (PSM session hijack, PRA session recording tampering), and the rotation layer (forcing rotation failure to keep credentials usable).

This skill emphasises realistic Kali Linux tooling: native HTTP clients (`curl`, `httpie`, `python-requests`) for vendor APIs, `WebSocket clients` for CyberArk WebSocket endpoints, `Impacket` and `psexec.py` for using harvested credentials, `mimikatz` and `SharpDPAPI` for credential file and DPAPI blob decryption on Windows footholds, `CyberArk-PSM-Decryptor` and `credential-file-parsers` for `.cue`/`.btl`/DPAPI-protected format decoding, vendor CLIs (`cyberark PowerShell module`, `Delinea API SDK`, `ManageEngine PMP REST client`), `CyberArk ` `PACLI` and `parcli` tooling, `BloodHound` for analysing PAM-aware group topology, and generic Kali tools (`nmap`, `gobuster`, `nuclei`) for the recon phase. Each pattern includes the relevant CVE (CVE-2025-32564 for CyberArk PVWA, CVE-2022-2451 for BeyondTrust SAML, CVE-2022-28226 for ManageEngine PMP) and vendor security advisory references where public CVEs do not exist.

The attack chain typically begins with PAM presence detection — identifying that the target runs CyberArk by finding `/PasswordVault/`, BeyondTrust via `/login.aspx` with `B` cookie prefix, Delinea Secret Server via `/SecretServer/`, ManageEngine PMP via the favicon hash and `/api/` endpoints. From there, the attacker enumerates the authentication surface, attempts credential stuffing (low-rate to evade PAM lockout policies), exploits vendor-specific auth bypass where present, and once inside, harvests every credential the compromised identity can reach. The endgame is rarely "staying inside the PAM" — it is using the PAM as a privileged credential firehose to dominate the downstream estate.

## Use Cases

1. **CyberArk PVWA Compromise Assessment** -- During an internal engagement, identify the CyberArk PVWA URL, attempt CVE-2025-32564-class authentication bypass, enumerate safes via the WebSocket interface, and demonstrate impact by extracting a Domain Admin credential from a low-privilege vault user.
2. **PSM Session Hijacking** -- From a foothold inside the PSM infrastructure, identify active PSM sessions, hijack the RDP/SSH session token, and pivot to the actual privileged target without re-authenticating.
3. **CyberArk Credential File (`.cue`) Decryption** -- Recover `.cue` credential files from the AIM/CCP provider cache or the EPV server, decrypt them with the master key or via operator key escrow weakness, and recover plaintext credentials.
4. **BeyondTrust PRA SAML Account Injection** -- Exploit CVE-2022-2451 to inject an unauthorised SAML identity into the PRA, granting remote privileged access without a local account.
5. **Delinea Secret Server OAuth Token Theft** -- From a foothold on a host running the Secret Server agent, extract the OAuth refresh token from the DPAPI-protected configuration, and use it to read secrets from the Secret Server API without the user's password.
6. **ManageEngine PMP PostgreSQL Backend Extraction** -- From a foothold on the PMP server, dump the embedded PostgreSQL backend, recover the encrypted credential table, and decrypt the AES-encrypted credentials using the PMP master key (typically stored in `pmp_key.key`).
7. **One Identity Safeguard SSL Pinning Bypass** -- Use Frida or Burp + a custom CA + pinning-bypass script to inspect the admin console's API surface, enabling the discovery of unauthenticated privileged session fabric endpoints.
8. **Just-in-Time Access Workflow Bypass** -- From a foothold that holds a stale JIT approval token, abuse the PAM's lack of session binding to extend the access window beyond the approved duration.
9. **PAM-Aware Pass-the-Hash** -- After compromising a credential that is currently checked out from the PAM and rotated on schedule, use the hash within the rotation window before the PAM forces the next change.
10. **Ransomware Operator PAM Playbook Validation (Purple Team)** -- In a defensive engagement, simulate the BlackCat PAM targeting playbook (initial access via VPN appliance → PAM enumeration → PAM compromise → mass credential retrieval → simultaneous ESXi/AD/cloud impact) and measure detection coverage.

## Core Tools

### Cross-Vendor Tools

| Tool | Category | Purpose |
|------|----------|---------|
| `curl` / `httpie` / `python-requests` | HTTP/HTTPS Recon & API | Universal vendor HTTP API probing |
| `websocat` / `python-websockets` | WebSocket Recon | CyberArk WebSocket safe enumeration |
| `nmap` / `nuclei` | Service Discovery | Identify PAM product by TLS/HTTP fingerprint |
| `gobuster` / `feroxbuster` | Path Discovery | Locate `/PasswordVault/`, `/SecretServer/`, `/api/` |
| `BloodHound` (SharpHound collector) | Topology Analysis | Map PAM-managed account → host edges |
| `Impacket` (`psexec.py`, `wmiexec.py`, `smbexec.py`) | Credential Use | Convert PAM-recovered credentials into shells |
| `mimikatz` / `SharpDPAPI` / `dpapi.py` (Impacket) | DPAPI Decryption | Decrypt DPAPI-protected PAM agent configs |
| `Frida` / `objection` | SSL Pinning Bypass | One Identity Safeguard, mobile PAM apps |
| `Burp Suite` / `mitmproxy` | API Interception | PAM HTTP API fuzzing, SAML response editing |
| `CyberChef` | Format Decoding | Decode `.cue`, base64, vendor-specific blob formats |

### Vendor-Specific Tools

| Tool | Vendor | Purpose |
|------|--------|---------|
| `CyberArk PS CLI` (`CyberArk-PasswordVault`) | CyberArk | Official PowerShell wrapper for PVWA REST API |
| `PACLI` | CyberArk | Legacy command-line Vault client (still deployed) |
| `parcli` / `capam1` | CyberArk | Community Vault utilities |
| `cyberark-psm-decryptor` (community) | CyberArk | Decrypt PSM-generated trace logs and cred files |
| `BeyondTrust API SDK` (`b pysafe`) | BeyondTrust | Python client for Password Safe / PRA API |
| `Delinea Secret Server SDK` | Delinea | .NET / PowerShell wrapper for SS REST API |
| `thycotic-python` (community) | Delinea | Python SDK for legacy Thycotic SS |
| `ManageEngine PMP REST SDK` | ManageEngine | Python wrapper for PMP API |
| `pmp-pgsql-dump` (community) | ManageEngine | PMP PostgreSQL backend dumper |
| `Safeguard API client` (`safeguard-bash`) | One Identity | Native shell client for Safeguard for Privileged Sessions (SPS) / Safeguard for Privileged Passwords (SPP) |
| `WALLIX Access Manager CLI` | WALLIX | `wabadmin` shell tooling |
| `Devolutions Server CLI` (`DVLS`) | Devolutions | PowerShell module for DVLS API |

## Methodology

### Phase 1: PAM Presence Reconnaissance

Identify which PAM product(s) the target runs before attempting vendor-specific attacks.

1. Identify web-facing PAM consoles via URL patterns (`/PasswordVault/` → CyberArk, `/SecretServer/` → Delinea, `/login.aspx` + BeyondTrust cookies → PRA, `/api/json/...` → ManageEngine PMP, `/sps/` → One Identity Safeguard, `/wab/` → WALLIX)
2. Fingerprint via TLS certificate SANs, favicon hashes, and HTTP header signatures (`Server: Microsoft-IIS` + `X-Powered-By: ASP.NET` → likely Delinea Secret Server or PRA)
3. Identify the supporting infrastructure: CyberArk EPV (Vault) on TCP/1858, AIM/CCP on TCP/443 + a `/AIMWebApi/` URL, PSM on RDP/3389, BeyondTrust PRA appliance, ManageEngine PMP on TCP/7272 (default), WALLIX Bastion on TCP/443 + SSH/22
4. Map DNS for naming patterns (`vault.`, `pam.`, `cyberark.`, `beyondtrust.`, `pmp-`, `safeguard-`, `bastion.`) to find management interfaces

### Phase 2: Authentication Surface Enumeration

Once the product is identified, enumerate every authentication path.

1. Map the login endpoints (form-based, SAML, OAuth, RADIUS-backed, LDAP-backed)
2. Identify the MFA enforcement surface (CyberArk `Risk-Based MFA`, BeyondTrust `2FA`, PMP `TFA`, Safeguard `smart card`)
3. Check for default/weak credentials (`cyberark/Admin123`, `boftelement/beyond`, `ssadmin/Admin123User`, `admin/admin`)
4. Identify CVE-specific authentication-bypass conditions (CVE-2025-32564 for PVWA `SMB` auth mode, CVE-2022-2451 for PRA SAML, CVE-2022-28226 for PMP path traversal pre-auth)

### Phase 3: Authentication and Initial Foothold

Obtain an authenticated session inside the PAM.

1. Apply vendor-specific auth bypass where applicable, or use harvested credentials from `secret-management-attack` or `phishing-attack` skills
2. Convert the authenticated session into a stable API token (CyberArk `<token>` via `/Auth/Roles/Logon`, BeyondTrust `Bearer` via `/oauth2/token`, Delinea `Bearer` via `/oauth2/token`, PMP via `/api/json/admin/getkey` API key flow)
3. Validate the token's scope (read-only vault user vs. safe owner vs. auditor vs. Enterprise admin)
4. Persist access via a long-lived refresh token or by creating a backdoor account where privilege allows

### Phase 4: Credential Enumeration and Extraction

Walk every safe/account the authenticated identity can reach and harvest credentials.

1. Enumerate safes (CyberArk `/PasswordVault/api/Safes`, BeyondTrust `/UserRoles/...`, Delinea `/v1/secrets`, PMP `/api/json/resources/list`, Safeguard `/v3/Assets`)
2. For each safe, enumerate accounts and pull the current credential value (password, SSH key, AWS key)
3. Where the API exposes a "show password" endpoint (CyberArk `/api/Accounts/<id>/Password/Retrieve`, Delinea `/v1/secrets/<id>/fields/password`), retrieve and immediately verify against the target
4. For credentials not exposed via API (CyberArk EPV-restricted, BeyondTrust checked-out), pivot to agent-side extraction (`.cue` file, DPAPI blob, agent config)

### Phase 5: PAM Lateral Movement and Downstream Exploitation

Use harvested credentials to dominate the actual privileged estate.

1. Identify each credential's target host from the safe metadata (CyberArk `address` field, BeyondTrust `AssetName`, Delinea `Secret.ServerName`)
2. Convert each credential into a foothold via the appropriate skill (`ad-ldap-attack` for AD accounts, `cloud-security` for cloud keys, `database-attack` for DB credentials, `network-pentest` for network device enable accounts)
3. Where the PAM is brokering sessions (PSM, PRA, Safeguard Sessions2), consider hijacking active sessions instead of re-authenticating
4. Cross-reference with BloodHound topology to identify which harvested credentials unlock the highest-value paths

### Phase 6: Persistence and Anti-Forensics

Establish durable access and reduce the forensic footprint.

1. Persist via the PAM itself — create a backdoor safe owner, register a rogue AIM application, or install a long-lived API key
2. JIT workflow abuse — issue standing access requests in cycles to maintain continuous access without an audit-time mass credential retrieval event
3. Session recording tampering — where session recording is in scope, identify the recording storage and the chain-of-custody controls; coordinated attackers (BlackCat) have been observed deleting session recordings as a step in the playbook
4. Audit log hygiene — understand what the PAM logs (`Vault Audit`, `ITAudit`, `ProcessLog`) and structure the access pattern to blend with normal operator traffic

## Practical Steps

### Step 1: Identify PAM Presence via URL Patterns

```bash
# CyberArk PVWA discovery
curl -sk -I https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/ | head -5

# Delinea Secret Server discovery
curl -sk -I https://REPLACE_WITH_YOUR_SS_HOST/SecretServer/ | head -5

# BeyondTrust PRA discovery (look for the auth/identity cookie prefixes)
curl -sk -I https://REPLACE_WITH_YOUR_PRA_HOST/login.aspx | grep -i 'set-cookie'

# ManageEngine PMP discovery (default port 7272)
curl -sk -I http://REPLACE_WITH_YOUR_PMP_HOST:7272/ | head -5

# One Identity Safeguard discovery
curl -sk -I https://REPLACE_WITH_YOUR_SG_HOST/sps/ | head -5

# WALLIX Bastion discovery
curl -sk -I https://REPLACE_WITH_YOUR_WAB_HOST:443/wab/ | head -5
```

### Step 2: CyberArk PVWA Authentication

```bash
# Standard logon (LDAP, CyberArk, RADIUS, SAML)
curl -sk -X POST -H 'Content-Type: application/json' \
  -d '{"username":"REPLACE_WITH_YOUR_VAULT_USER","password":"REPLACE_WITH_YOUR_VAULT_PASS"}' \
  https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/auth/Cyberark/Logon | jq -r .token

# Persist the token
TOKEN=$(curl -sk -X POST -H 'Content-Type: application/json' \
  -d '{"username":"REPLACE_WITH_YOUR_VAULT_USER","password":"REPLACE_WITH_YOUR_VAULT_PASS"}' \
  https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/auth/Cyberark/Logon | jq -r .token)

# Validate the session
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Session/Verify
```

### Step 3: Enumerate CyberArk Safes

```bash
# List every safe the token can see
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Safes \
  | jq '.Safes[] | {SafeName, NumberOfAccounts, ManageMembers}'

# Enumerate accounts in a target safe
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts?filter=safename eq REPLACE_WITH_YOUR_SAFE_NAME" \
  | jq '.value[] | {name, address, userName}'
```

### Step 4: CyberArk Credential Retrieval

```bash
# Retrieve the current password value of an account
curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts/REPLACE_WITH_YOUR_ACCT_ID/Password/Retrieve \
  -d '{"reason":"incident-response","TicketingSystemName":"jira"}' | jq -r .password

# Retrieve SSH keys (returns PEM)
curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  https://REPLACE_WITH_YOUR_PVWA_HOST/PasswordVault/api/Accounts/REPLACE_WITH_YOUR_ACCT_ID/Secret/Retrieve \
  -d '{"reason":"incident-response"}'
```

### Step 5: BeyondTrust PRA API Authentication

```bash
# Acquire OAuth bearer token (alternative: API key via System Settings > API Configuration)
BT_TOKEN=$(curl -sk -X POST \
  -u 'REPLACE_WITH_YOUR_API_KEY:' \
  -d 'grant_type=client_credentials' \
  https://REPLACE_WITH_YOUR_PRA_HOST/api/oauth2/token | jq -r .access_token)

# Validate
curl -sk -H "Authorization: Bearer $BT_TOKEN" \
  https://REPLACE_WITH_YOUR_PRA_HOST/api/v1/auth/whoami
```

### Step 6: ManageEngine PMP API Key Enumeration

```bash
# Acquire the API token via the admin API key flow
PMP_TOKEN=$(curl -sk -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=REPLACE_WITH_YOUR_PMP_USER&password=REPLACE_WITH_YOUR_PMP_PASS' \
  https://REPLACE_WITH_YOUR_PMP_HOST:7272/api/json/admin/getkey \
  | jq -r .api_key)

# Enumerate resources (the password stores / accounts PMP manages)
curl -sk -H "AUTHTOKEN=$PMP_TOKEN" \
  'https://REPLACE_WITH_YOUR_PMP_HOST:7272/api/json/resources/list' | jq .

# Pull the password for a specific resource
curl -sk -H "AUTHTOKEN=$PMP_TOKEN" \
  'https://REPLACE_WITH_YOUR_PMP_HOST:7272/api/json/resource/REPLACE_WITH_YOUR_RES_ID/getPasswordAccountDetails' | jq .
```

### Step 7: Delinea Secret Server OAuth Flow

```bash
# OAuth token via password grant (deprecated but still common)
SS_TOKEN=$(curl -sk -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=password&username=REPLACE_WITH_YOUR_SS_USER&password=REPLACE_WITH_YOUR_SS_PASS' \
  https://REPLACE_WITH_YOUR_SS_HOST/SecretServer/oauth2/token | jq -r .access_token)

# Enumerate folders and secrets
curl -sk -H "Authorization: Bearer $SS_TOKEN" \
  https://REPLACE_WITH_YOUR_SS_HOST/api/v1/folders | jq .

curl -sk -H "Authorization: Bearer $SS_TOKEN" \
  https://REPLACE_WITH_YOUR_SS_HOST/api/v1/secrets | jq '.records[] | {id, name, secretTemplateName}'
```

### Step 8: Convert a Harvested Credential to a Foothold

```bash
# Given a Domain Admin credential recovered from CyberArk
DOMAIN='REPLACE_WITH_YOUR_DOMAIN'
USER='REPLACE_WITH_YOUR_DA_NAME'
PASS='REPLACE_WITH_YOUR_DA_PASS'
DC_IP='REPLACE_WITH_YOUR_DC_IP'

# Verify against LDAP
ldapsearch -x -H "ldap://$DC_IP" -D "$DOMAIN\\$USER" -w "$PASS" -s sub -b "" namingcontexts | head -5

# Use the credential to dump domain hashes (no prior foothold needed)
impacket-secretsdump "$DOMAIN/$USER:$PASS@$DC_IP" | head -20

# Use Impacket's psexec to obtain a shell as the DA
impacket-psexec "$DOMAIN/$USER:$PASS@$DC_IP"
```

### Defense Perspective

### Detecting PAM Attacks

- **Authentication anomalies** -- CyberArk PVWA logs every Logon event to the Vault Audit. A burst of failed logons followed by a success from a new IP is high-signal. BeyondTrust PRA logs to the appliance audit + optionally to SIEM. Delinea SS Event Framework exposes `LoginEvent`, `SecretViewEvent`, `SecretAccessEvent`. ManageEngine PMP logs to its own audit table (`pmpaudits`).
- **API enumeration patterns** -- CyberArk `List Safes` calls beyond an operator's normal cadence appear in ITAudit as `Action=Get Safes List`. Delinea SS reports repeated `GET /api/v1/secrets` from a single session as a Mass Secret Access event (configurable in Event Policies).
- **Credential retrieval volume** -- Any user retrieving more than N credentials in a short window is suspect. Define and alert on a baseline per role.
- **PSM / PRA session anomalies** -- Concurrent sessions, session starts from new IPs, or session recording interruptions (recording failed) are all red flags.
- **Post-compromise tampering** -- Bulk deletion of audit log entries, mass safe deletion, or disabling of session recording are immediate indicators of post-breach cleanup.
- **Credential file discovery** -- Finding `.cue`, `.btl`, `Vault.ini`, `agent_config.xml`, `pmp_key.key`, `safeguard-settings.json` outside of the expected runtime path indicates either agent misconfiguration or an attacker staging for extraction.

### Mitigations per Vendor

- **CyberArk** -- Enforce Risk-Based MFA on PVWA, restrict `List Safes` to authenticated EPV users, harden the EPV server (`AllowDirectLogon=No` on `paragent`), patch PVWA to current release (CVE-2025-32564-class fixes), enable `RequireDualControl` on Tier-0 safes, monitor `ITAudit` for `GetPassword` events
- **BeyondTrust** -- Patch PRA (CVE-2022-2451 fix), enforce endpoint certificates, restrict SAML IdP to known IdPs only, enable session recording tamper-evidence, monitor Password Safe API for anomalous bulk read
- **Delinea** -- Migrate off password grant in OAuth (use authorization code + PKCE), enforce DPAPI-protected configuration, restrict distributed engine outbound to known SS only, enable the `EventPipeline` for SIEM streaming
- **One Identity** -- Keep SSL pinning enabled, monitor Safeguard for Privileged Passwords (SPP) session fabric events, enforce smart card MFA on admin console
- **ManageEngine** -- Patch PMP (CVE-2022-28226-class fixes), restrict API key scope, encrypt the PMP PostgreSQL backend at rest, rotate the PMP master key annually
- **Cross-cutting** -- Enforce JIT access over standing access, implement transaction-based access (per-request approval), integrate PAM events into the SIEM with the high-fidelity event list above

### Hardening Recommendations

- **Tiering** -- Never let Tier-0 credentials (Domain Admin, Enterprise Admin) be reachable from Tier-1 or Tier-2 hosts. The PAM enforces the boundary.
- **JIT over standing** -- Default-deny standing privileged access; every privileged session should require an explicit, time-boxed, audited approval.
- **Session brokering** -- Force all privileged access through PSM/PRA/Sessions2 so the credential is never exposed to the operator or the endpoint.
- **Credential rotation** -- Rotate after every session, on schedule, and on personnel change.
- **Audit streaming** -- Stream PAM audit events in real time to a SIEM that has a baseline of normal operator behaviour. Anomalous bulk-read events should page the SOC.
- **PAM-as-a-target hardening** -- Treat the PAM itself as a Tier-0 asset: hardened underlying OS, restricted management interfaces, HSM-backed key storage, signed agent code, transparent chain of custody on session recordings.

## Key References

- **CVE-2025-32564 (CyberArk PVWA)** -- CyberArk Security Advisory, 2025. Authentication bypass class affecting Password Vault Web Access. Vendor advisory under `cyberark.com/security`".
- **CVE-2022-2451 (BeyondTrust PRA / Identity Security Insights)** -- BeyondTrust Security Advisory BTN-2022-04, 2022. SAML account injection allowing unauthorised privileged remote access.
- **CVE-2022-28226 (ManageEngine Password Manager Pro)** -- ManageEngine Security Advisory, 2022. Pre-auth path traversal enabling access to restricted API endpoints.
- **Mandiant: BlackCat / ALPHV Ransomware Targeting PAM** -- Mandiant Threat Intelligence report, 2023. Documents the BlackCat affiliate playbook that includes explicit PAM enumeration and compromise as a step.
- **CrowdStrike: LockBit 3.0 Affiliate Manual (leaked)** -- CrowdStrike analysis of the September 2022 LockBit builder leak, which references CyberArk credential retrieval as a step in the lateral movement phase.
- **Variable Threat / Royal-BlackSuit Advisory** -- Vendor and IR-firm analyses of the Royal / BlackSuit affiliate playbook's BeyondTrust abuse step.
- **CyberArk PSMS Decryption PoC** -- Community research on `.cue` file format and operator key escrow weakness, 2022.
- **One Identity Safeguard for Privileged Passwords Admin Guide** -- Section on SSL pinning and privileged session fabric hardening.
- **Delinea Secret Server Distributed Engine Architecture Guide** -- Documents the DPAPI-protected agent config and the OAuth refresh-token flow.

## Tool Installation Reference

```bash
# Generic dependencies
sudo apt update
sudo apt install -y curl httpie python3-pip websocat nmap gobuster

# Impacket (for using harvested credentials downstream)
python3 -m pip install --upgrade impacket

# BloodHound (for topology analysis)
# Download from https://github.com/SpecterOps/BloodHound/releases
# SharpHound collector on a Windows foothold

# CyberArk PowerShell module (run from a Windows foothold or PowerShell on Linux)
# Install-Module -Name CyberArk-PasswordVault -Scope CurrentUser

# Delinea Secret Server .NET SDK (Windows-only)
# Install via NuGet: Thycotic.SecretServer

# ManageEngine PMP REST client (Python community SDK)
python3 -m pip install manageengine-pmp-client

# Safeguard API client (community)
sudo apt install -y safeguard-bash  # or git clone https://github.com/OneIdentity/safeguard-bash

# Frida (for SSL pinning bypass on Safeguard admin console or mobile apps)
python3 -m pip install frida-tools

# mitmproxy / Burp Suite Community
# Burp: https://portswigger.net/burp/communitydownload
# mitmproxy:
python3 -m pip install --upgrade mitmproxy

# CyberChef (browser-based format decoding)
# Clone locally:
git clone https://github.com/gchq/CyberChef.git
```

## Vendor Quick Decision Matrix

| Scenario | Path | Tool | Notes |
|----------|------|------|-------|
| URL pattern `/PasswordVault/` | CyberArk | `curl` + `cyberark-ps` | First check the auth mode (Cyberark / LDAP / SAML / RADIUS) |
| URL pattern `/SecretServer/` | Delinea (Thycotic) | `curl` + Delinea SDK | Check OAuth grant_type |
| URL pattern `/login.aspx` + `BT*` cookies | BeyondTrust PRA | `curl` + BeyondTrust SDK | Patch level: BTN-2022-04 (CVE-2022-2451) |
| URL pattern `/api/json/...` on :7272 | ManageEngine PMP | `curl` + PMP SDK | Patch level: CVE-2022-28226 |
| URL pattern `/sps/` | One Identity Safeguard | `safeguard-bash`, Frida | SSL pinning on admin console |
| URL pattern `/wab/` | WALLIX Bastion | `wabadmin` | Often fronted by Apache |
| Need PSM session access | CyberArk PSM | RDP to PSM with vault creds | Watch for session recording |
| Need credential from inside an AIM/CCP agent | CyberArk AIM | `.cue` file + master key | Aim for the `Vault.ini` + provider cache |
| Need DPAPI-protected agent config | Delinea / BeyondTrust | `SharpDPAPI` on Windows foothold | DPAPI blob under `%PROGRAMDATA%` |
| Need to bypass JIT workflow | Any PAM with JIT | Replay stale approval token | JIT bypass requires careful OPSEC |
| Ransomware operator playbook | BlackCat / LockBit / Royal | Purple team replay | Map the full PAM step in the playbook |

## Anti-Forensics and OPSEC Considerations

- **Audit log entries persist** -- CyberArk Vault Audit is append-only by design; deleting records requires Enterprise-admin-level rights and is itself logged. ManageEngine PMP audits are in PostgreSQL; tampering requires backend access. BeyondTrust PRA audit is on the appliance; tamper-evident if streaming to SIEM is enabled.
- **API enumeration is loud** -- A single `GET /api/Safes` is normal; enumerating 500 safes in 30 seconds is high-signal. Pace enumeration to match operator behaviour and use the legitimate `query` filters rather than `list all`.
- **Credential retrieval is logged with a reason field** -- CyberArk, Delinea, and BeyondTrust all log the operator-supplied "reason" or "ticket" string. Use a realistic reason that matches the engagement's IR context.
- **Session recording gaps** -- PSM/PRA/Sessions2 all record by default. A session without a recording, or with a recording shorter than the session duration, is a red flag. Time operations to align with high-traffic windows where recording gaps are normal.
- **PSM connection patterns** -- PSM connects via RDP from a fixed IP range (the PSM pool). Connections from outside that range are immediate red flags.
- **DPAPI blob extraction** -- SharpDPAPI execution is detected by modern EDR. Consider `sekurlsa::dpapi` from mimikatz with OPSEC flags, or exfil the blob and decrypt offline.

## Scope Boundaries

This skill does **not** cover:

- Generic secrets in source code, CI/CD pipelines, or cloud secret managers (AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault) -- see `secret-management-attack`
- Active Directory Kerberos / NTLM / PKI attacks against the domain controller -- see `ad-ldap-attack` and `ad-cs-abuse`
- Endpoint privilege elevation (local root / SYSTEM escalation, UAC bypass) -- see `privilege-escalation` and `privilege-escalation-windows`
- Mobile device management (MDM) and mobile threat defence (MTD) -- out of scope for vendor-PAM
- Privileged identity in cloud providers (AWS IAM Identity Center, Entra PIM) -- see `cloud-identity-attack`

When an engagement crosses into any of these, chain the relevant skill in sequence. PAM compromise is typically a mid-engagement step that produces material the other skills consume downstream.
## Detection Methods

### PAM Vendor Audit
- **CyberArk PVWA anomalies**: Login from new geo; password access spike.
- **BeyondTrust PRA anomalies**: Session recording disabled; new endpoint registered.
- **Delinea/One Identity**: Secret retrieval spike; new endpoint with broad secret access.
- **ManageEngine PMP**: API token abuse; bulk password retrieval.

### SIEM Detection Rules
- **Splunk SPL**: `index=pam vendor="CyberArk" | stats count by user, action | where action="retrieve_password" | sort -count`
- **Cyberark EPV / BeyondTrust logs**: Native SIEM integration.

## Defense Evasion Techniques

### PAM Compromise Stealth
- **Use legitimate session recording gaps**: Exploit maintenance windows where recording disabled.
- **Use legitimate service account**: Compromise service account that has PAM access; appears as legitimate admin.
- **Off-hours access**: Access PAM during low-activity hours; less attention.

### Credential Theft Stealth
- **Use existing API tokens**: Steal long-lived API tokens; no auth events triggered.
- **Bypass dual control**: Use emergency access (Break Glass) credential; less audit.
- **Retrieve then use later**: Retrieve secret once, use outside PAM audit window.

