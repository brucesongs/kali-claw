# Cloud Identity Attack — Real-World Incident Case Studies

> Companion guide to `SKILL.md` and `payloads.md`. This file catalogs twelve landmark cloud-identity breaches (2020-2024) so that red teamers can map historical attacker tradecraft to current engagement objectives, and so that defenders can calibrate detection gaps.

---

## Overview

Cloud identity providers (Entra ID, Okta, Auth0, Ping, ADFS) have become the de facto keys to the enterprise kingdom. A single compromised Global Admin, forged SAML assertion, or illicitly-consented OAuth grant can collapse an otherwise hardened perimeter. The twelve incidents below were chosen because each highlights a distinct identity failure mode — SAML forgery, MFA fatigue, OAuth consent phishing, session token theft, supply-chain backdoor, credential stuffing, helpdesk social engineering, and more. Every case includes the timeline, the precise identity technique the attacker abused, the detection gap that allowed it, and the offensive lesson that red teamers should internalize.

When studying these, note the recurring themes: (1) identity is the new perimeter, (2) MFA is necessary but not sufficient — the MFA *implementation* matters, (3) service principals and OAuth grants are blindly trusted, (4) helpdesk and support staff are high-value identity targets, and (5) cross-cloud pivots via SAML/OAuth federation turn a single IdP breach into a multi-cloud catastrophe.

---

## Case 1: SolarWinds SUNBURST — AAD Backdoor (SAML)

**Timeline (2020)**: UNC2452 / NOBELIUM (Microsoft's designation: Midnight Blizzard / APT29) compromised the SolarWinds build pipeline and shipped the SUNBURST backdoor to ~18,000 Orion customers. At a subset of high-value victims, the attacker pivoted from on-prem into Microsoft 365 / Entra ID by forging SAML assertions using the AD FS token-signing certificate (Golden SAML). Microsoft's own corporate systems were breached via this path.

**Identity technique**: Golden SAML. The attacker extracted the AD FS TokenSigning certificate from the on-prem AD DS (DKM-protected container) using Domain Admin privileges, then used AADInternals (`New-AADIntSAMLToken`) to forge assertions impersonating any user. The forged assertion included an MFA claim, satisfying Entra ID Conditional Access without a real second factor. Because the assertion is cryptographically signed by the trusted federation key, Entra ID accepts it as authoritative.

**Detection gap**: Entra ID sign-in logs showed the federated user authenticating "successfully" — there was no anomaly because the signature was valid. The only telltale was the `Issuer` URI matching `http://adfs.corp.com/adfs/services/trust` and unusual client IP / app ID combinations. Many victims lacked federation-aware SIEM rules.

**Red team lesson**: If the engagement scope includes on-prem AD and the target federates with Entra ID via AD FS, Golden SAML is the highest-impact single action. Prioritize the AD FS server, the DKM share path, and the `ADFSDKMContainer` in AD.

---

## Case 2: Lapsus$ — Microsoft / Okta Account Takeover (2022)

**Timeline (Mar 2022)**: The Lapsus$ group (Microsoft designation: Strawberry Tempest) claimed compromise of Microsoft, Okta, Samsung, Nvidia, Ubisoft, and others. The Microsoft breach was confirmed on Mar 22, 2022; Okta confirmed on Mar 22 that an Okta support engineer's workstation had been accessed by the group in Jan 2022, enabling limited customer token theft.

**Identity technique**: Social engineering of helpdesk / privileged insiders + MFA fatigue. Lapsus$ obtained initial access by (a) buying credentials on criminal marketplaces (e.g., Russian Market / Genesis), (b) recruiting employees via Telegram for cash, and (c) bombarding enrolled MFA devices with push prompts until the user approved. Once inside, they targeted the helpdesk to reset MFA on additional accounts.

**Detection gap**: Helpdesk MFA resets were not anomaly-flagged; the org treated "user requested MFA reset" as routine. Push-based MFA provided no cryptographic assurance of the *user's intent*, only the *device's presence*.

**Red team lesson**: Helpdesk social engineering and MFA push fatigue are reliable initial access vectors. Engagement playbooks should include a (consented) MFA fatigue simulation against test users (see TC-CI-008).

---

## Case 3: Uber MFA Fatigue Attack (2022)

**Timeline (Sep 15, 2022)**: An 18-year-old attacker gained access to Uber's internal systems by spamming an Uber engineer's MFA app with push notifications until the engineer approved one. From there, the attacker found a PowerShell script containing hardcoded credentials for a privileged admin, pivoting to AWS, GCP, SentinelOne, and Duo admin consoles.

**Identity technique**: MFA push fatigue ("push-bombing") targeting a user who had self-enrolled in push-based MFA. Uber's MFA at the time allowed repeated unsolicited pushes — no number-matching, no rate limit.

**Detection gap**: Uber's SIEM did not correlate "50 MFA pushes in 30s" with an attack. The Duo admin console itself was reachable from the engineer's compromised session, allowing MFA device de-enrollment for other users.

**Red team lesson**: Number-matching (Microsoft Authenticator default since May 2023) materially raises the bar, but Okta Verify, Duo, and SMS-based MFA are still fatigue-vulnerable. Engagements should always test the MFA vendor's rate-limiting posture.

---

## Case 4: Midnight Blizzard — Microsoft Corporate Email (2024)

**Timeline (Nov 2023 - Jan 2024)**: Microsoft disclosed on Jan 12, 2024 that Midnight Blizzard (APT29 / NOBELIUM) had used a password-spray attack against a legacy test tenant account that lacked MFA. The account had `TestTenantAdmin`-style privileges and was used to access Microsoft corporate email of senior leadership and the cybersecurity team.

**Identity technique**: Password spray against an unmonitored test account with no MFA. Once in, the attacker used the account's OAuth permissions to create a malicious app registration in the test tenant, then used the app to read mail in the corporate tenant via cross-tenant federation trust.

**Detection gap**: Test tenant activity was not mirrored to corporate SIEM. Microsoft had not enforced MFA on the legacy tenant. App registration by a non-developer account was not anomaly-flagged.

**Red team lesson**: Always enumerate test/dev/sandbox tenants during recon (TC-CI-001). They often inherit federation trust without inheriting hardening.

---

## Case 5: Okta Support System Breach (2023, 1Password, BeyondTrust affected)

**Timeline (Oct 2023)**: BeyondTrust disclosed on Oct 2 that an Okta support case had leaked a HAR file containing a valid session cookie. 1Password disclosed Oct 4 that the same actor accessed its Okta tenant via a session token in the HAR. Cloudflare also disclosed compromise. Okta confirmed Oct 20 that 1Password's session had been abused to access their internal admin panel.

**Identity technique**: Session cookie theft via a HAR file uploaded to Okta support. The cookie (the `sid` cookie) was valid until session expiry. The attacker replayed the cookie from their own IP, authenticating as the 1Password admin without MFA challenge (the session had already been MFA'd at creation).

**Detection gap**: 1Password's SIEM did not flag "session cookie used from new geolocation / ASN." Okta's session binding was to the cookie, not to device posture.

**Red team lesson**: Session token theft (via HAR files, browser cookie extraction, LSASS dump for WAM tokens) bypasses MFA entirely. Engagements should include session-cookie replay testing — particularly for Okta and Entra ID.

---

## Case 6: 23andMe Credential Stuffing (2023)

**Timeline (Oct 2023)**: 23andMe disclosed that attackers had used credential stuffing (recycled passwords from other breaches) to compromise ~14,000 accounts, then used those accounts' "DNA Relatives" feature to scrape data on 6.9 million additional users.

**Identity technique**: Automated credential stuffing against the 23andMe web login. No MFA was enforced at the time. The attacker (Golem, on BreachForums) used a credential list compiled from historical breaches.

**Detection gap**: 23andMe's login rate-limiting and anomaly detection failed to flag 14,000 successful logins from a narrow ASN range in a short window.

**Red team lesson**: Any externally-facing identity endpoint without rate-limiting and credential-stuffing detection (e.g., FIDO2, MFA, smart lockout) is a target. Red teamers should test password-spray posture on every customer-facing IdP.

---

## Case 7: Twilio / Cloudflare Phish (2022)

**Timeline (Aug 2022, "Oktapus")**: The threat actor group "0ktapus" (later attributed to Scattered Spider) sent SMS messages to Twilio and Cloudflare employees pointing to a fake Okta login page. ~135 Twilio employees entered credentials. Cloudflare detected the attack via hardware security keys (FIDO2).

**Identity technique**: AiTM (adversary-in-the-middle) phishing. The fake page proxied the real Okta login in real-time, capturing credentials, MFA token, and the resulting session cookie. The cookie was then replayed.

**Detection gap**: Twilio's MFA was TOTP-based — fully proxied by AiTM. Cloudflare's MFA was FIDO2 / WebAuthn, which is cryptographically origin-bound and refused to authenticate to the fake domain.

**Red team lesson**: AiTM phishing is the modern baseline for credential attacks. The only effective defense is FIDO2 / phishing-resistant MFA. Red team engagements should evaluate whether the target's MFA is phishing-resistant.

---

## Case 8: Mailchimp OAuth Abuse (2022-2023)

**Timeline (Jan 2023)**: Mailchimp disclosed that an attacker had used OAuth social engineering to access 133 customer accounts. The attacker called Mailchimp support, impersonated employees of target companies, and convinced support staff to issue OAuth tokens to the attacker-controlled app.

**Identity technique**: OAuth grant abuse via social engineering of the IdP vendor's own staff. The attacker manipulated the support workflow to grant the malicious app `mail.read` and `mail.send` scopes.

**Detection gap**: OAuth grant issuance was not gated by additional verification beyond the support interaction.

**Red team lesson**: OAuth consent and grant issuance are privileged operations. Engagements targeting SaaS IdPs should enumerate which staff can issue grants, and whether consent-phishing of users is feasible (TC-CI-004).

---

## Case 9: Cisco Talos Breach (2022)

**Timeline (Aug 2022)**: Cisco confirmed that the Yanluowang ransomware group (later linked to UNC3524 / Scattered Spider) had compromised an employee's personal Google account, harvested from a password-synced browser profile, then used that credential against Cisco's VPN. The personal Google account password was reused as the Cisco VPN password.

**Identity technique**: Credential reuse. The attacker did not phish Cisco directly — they compromised a personal Google account via a separate breach and replayed the credential against Cisco VPN. The Cisco VPN enforced MFA via SMS, which the attacker then social-engineered via voice phishing (vishing) to intercept.

**Detection gap**: Cisco's VPN did not detect "credential valid but device fingerprint new" as anomalous. SMS-based MFA was interceptable via SIM-swap or voice-phishing.

**Red team lesson**: Identity protection extends beyond corporate identities. Personal-account credential reuse is a real initial access vector. Red teamers should evaluate whether the target's VPN / IdP enforces phishing-resistant MFA.

---

## Case 10: Mint Sandstorm Microsoft Account Takeover (2023)

**Timeline (Aug 2023)**: Microsoft disclosed that Mint Sandstorm (formerly PHOSPHORUS / Charming Kitten / APT35, an Iranian group) had targeted hundreds of organizations using a combination of password spray and MFA fatigue. The MFA fatigue technique was applied against accounts that had push-based MFA, repeating pushes until approval.

**Identity technique**: Password spray followed by MFA fatigue. Mint Sandstorm used rotating IP infrastructure (residential proxies) to evade smart lockout. Once a user approved a push, the attacker pivoted to OAuth app abuse for persistence.

**Detection gap**: Microsoft's own anomaly detection eventually flagged the campaign, but many customers had been compromised for weeks.

**Red team lesson**: State-sponsored groups operationalize the same techniques red teamers use. Engagements should validate that Conditional Access policies include device posture, trusted-location, and session risk.

---

## Case 11: Scattered Spider — Caesar Entertainment / MGM (2023)

**Timeline (Sep 2023)**: Scattered Spider (UNC3944) vished the MGM Resorts helpdesk, impersonating an IT employee. The helpdesk reset the employee's MFA, granting the attacker access to Okta and then to the on-prem AD. Within hours, MGM slot machines went dark. Caesar Entertainment was hit separately — the attacker demanded and received a $15M ransom. The same group had earlier hit Twilio, Riot Games, and DoorDash.

**Identity technique**: Helpdesk vishing to reset MFA on a privileged account. The attacker used OSINT (LinkedIn, public LinkedIn Learning, social media) to impersonate the employee convincingly. After MFA reset, the Okta SSO session granted access to ~30 downstream SaaS apps.

**Detection gap**: Helpdesk MFA reset was treated as routine. The identity of the caller was not verified beyond a "knowledge" check.

**Red team lesson**: Helpdesk social engineering is the single highest-impact identity attack against large orgs. Engagements should test the helpdesk MFA-reset workflow (with consent) and recommend identity verification (manager callback, hardware token check).

---

## Case 12: Snowflake UNC5537 Account Takeover (2024)

**Timeline (Apr-Jun 2024)**: Mandiant attributed a campaign that breached ~165 Snowflake customer tenants to UNC5537 (also linked to Scattered Spider). The attacker used credentials stolen via Infostealer malware (e.g., Racoon, RedLine) from customer environments, and abused Snowflake's lack of mandatory MFA. Affected customers included Ticketmaster (560M records), AT&T, LendingTree, and Santander.

**Identity technique**: Infostealer credential replay. Snowflake's default configuration did not enforce MFA; UNC5537 simply replayed stolen credentials. The attacker then used Snowflake's own data-extraction API to dump customer tables.

**Detection gap**: Snowflake did not enforce MFA at the platform level until after the campaign. Customer SIEMs had limited visibility into Snowflake activity.

**Red team lesson**: SaaS-IdP / data-platform credentials are valuable on the resale market. Red team engagements targeting data warehouses (Snowflake, Databricks, BigQuery) should test credential-replay and MFA-enforcement posture.

---

## Hands-on: Cross-Case Pattern Analysis

To operationalize these lessons in a current engagement, run the following Microsoft Graph and Azure CLI commands to assess your own tenant's exposure:

### Step 1: Enumerate MFA-Excluded Users

```bash
# List users excluded from MFA registration policy
az rest --method get --url "https://graph.microsoft.com/beta/reports/credentialUserRegistrationDetails" \
  --query "value[?isMfaRegistered == false] | [].userPrincipalName"
```

### Step 2: Audit OAuth Consent Grants

```powershell
# Find all OAuth2 grants (user + app consents)
Connect-MgGraph -Scopes "Directory.Read.All"
Get-MgServicePrincipalOauth2PermissionGrant -All | 
  Select-Object Id, ClientId, ConsentType, Scope, ResourceId
# Flag any grant with "Mail.Read" or "Directory.ReadWrite.All" for non-Microsoft apps
```

### Step 3: Detect Illicit Admin Consent

```bash
# Identify tenant-wide (admin consent) grants to non-Microsoft apps
az rest --method get --url "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?\$filter=consentType eq 'AllPrincipals'" \
  --query "value[?!startswith(displayName,'Microsoft')]"
```

### Step 4: Audit PIM Eligibility Coverage

```bash
# Confirm that Global Admins are PIM-eligible (not standing)
az rest --method get --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$filter=roleDefinitionId eq '62e90394-69f5-4237-9190-000e28d0201c'" \
  --query "value[].{principal:principalId, type:assignmentType}"
```

### Step 5: Check Legacy Auth Posture

```powershell
# Confirm legacy auth is blocked
Connect-ExchangeOnline
Get-TransportConfig | Select-Object -ExpandProperty SmtpClientAuthenticationEnabled
# Should be False in hardened tenants
```

---

## References

1. CISA Alert AA21-008A — SUNBURST / NOBELIUM supply chain compromise — https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-008a
2. Microsoft Security Response Center — Midnight Blizzard corporate email breach (Jan 2024) — https://msrc.microsoft.com/blog/2024/01/microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard/
3. Mandiant — UNC5537 Snowflake campaign report (Jun 2024) — https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-campaign
4. CISA Alert AA22-040A — Lapsus$ tradecraft — https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-040a
5. Uber Security Update — Sep 15, 2022 MFA fatigue incident — https://www.uber.com/newsroom/security-update/
6. Okta Customer Advisory — HAR file / support system breach (Oct 2023) — https://sec.okta.com/harfilesadvisory
7. 1Password Statement — Okta session token abuse (Oct 2023) — https://blog.1password.com/recent-okta-security-incident/
8. CrowdStrike — Scattered Spider / UNC3944 threat profile — https://www.crowdstrike.com/blog/scattered-spider-analysis/
9. Cloudflare — Oktapus / Twilio phishing analysis (Aug 2022) — https://blog.cloudflare.com/2022-07-sms-phishing-attacks/
10. Microsoft Threat Intelligence — Mint Sandstorm MFA fatigue campaign — https://www.microsoft.com/en-us/security/blog/2023/08/28/mint-sandstorm-threat/
11. Cisco PSIRT — Yanluowang / Talos breach advisory (Aug 2022) — https://blog.talosintelligence.com/recent-cyber-attack/
12. 23andMe Incident Report (Oct 2023) — https://www.23andme.com/technical-update/
13. Microsoft — Detection and mitigation of Golden SAML — https://www.microsoft.com/en-us/security/blog/2021/01/06/detecting-and-mitigating-adfs-token-signing-certificate-abuse/
14. Mandiant — AiTM phishing kit analysis — https://www.mandiant.com/resources/blog/aitm-phishing-kit
